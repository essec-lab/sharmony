///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Strict duet-mode KAT runner for SHA-224 / SHA-256, two-phase (matches
// HashKatTest):
//   Phase 1  reset() BEFORE every vector.
//   Phase 2  ONE reset() at vector 0, then all vectors CHAINED (no per-vector
//            reset; each relies on the DUT returning to idle on its own).
// A vector PASSES only when, for every beat i, got_beats[i] == {md_i, md_i}
// (both hi and lo lanes equal the expected MD word). The test passes only if
// BOTH phases pass every vector.
//
///////////////////////////////////////////////////////////////////////////////////////

#include "HashKatDuetTest.hpp"
#include "../../RspParser.hpp"

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace sharmony {

static std::string msgPreview(const std::vector<uint8_t>& m) {
    if (m.empty()) return "(empty)";
    if (m.size() <= 32) return SharmonyDriver::bytesToHex(m);
    std::vector<uint8_t> head(m.begin(), m.begin() + 16);
    std::vector<uint8_t> tail(m.end() - 16, m.end());
    return SharmonyDriver::bytesToHex(head) + "..."
         + SharmonyDriver::bytesToHex(tail);
}

static std::vector<uint64_t> mdToDuetBeats(const std::vector<uint8_t>& md, int n_beats) {
    std::vector<uint64_t> out(n_beats, 0);
    for (int i = 0; i < n_beats; i++) {
        uint32_t w = (uint32_t(md[4*i + 0]) << 24)
                   | (uint32_t(md[4*i + 1]) << 16)
                   | (uint32_t(md[4*i + 2]) <<  8)
                   |  uint32_t(md[4*i + 3]);
        out[i] = (uint64_t(w) << 32) | uint64_t(w);
    }
    return out;
}

static std::string hex64(uint64_t v) {
    std::ostringstream os;
    os << std::hex << std::setw(16) << std::setfill('0') << v;
    return os.str();
}
static std::string hex32(uint32_t v) {
    std::ostringstream os;
    os << std::hex << std::setw(8) << std::setfill('0') << v;
    return os.str();
}

static const char* describeBeatFailure(uint64_t got, uint64_t expected) {
    uint32_t got_hi = uint32_t(got >> 32);
    uint32_t got_lo = uint32_t(got & 0xFFFFFFFFULL);
    uint32_t exp_w  = uint32_t(expected & 0xFFFFFFFFULL);
    const bool hi_ok = (got_hi == exp_w);
    const bool lo_ok = (got_lo == exp_w);
    if      ( hi_ok && !lo_ok) return "lo-lane only";
    else if (!hi_ok &&  lo_ok) return "hi-lane only";
    else if (got_hi == got_lo) return "both lanes (agree on wrong value)";
    else                       return "both lanes (diverge)";
}

int runHashKatDuet(SharmonyDriver& drv,
                   const TestOptions& opts,
                   Mode mode,
                   const std::string& default_rsp,
                   const std::string& testlabel) {
    const std::string path = opts.rsp_path.empty() ? default_rsp : opts.rsp_path;

    std::vector<RspVector> vectors;
    try {
        vectors = parseRsp(path);
    } catch (const RspParseError& e) {
        std::cerr << "[" << testlabel << "] RSP parse error: " << e.what() << "\n";
        return 2;
    }

    std::cout << "[" << testlabel << "] " << vectors.size()
              << " vectors loaded from " << path
              << " (duet mirror, strict per-lane check)\n";

    const int n_beats    = digestBeatsFor(mode);     // 7 / 8
    const int n_md_bytes = digestBytesFor(mode);     // 28 / 32

    if ((int)(n_beats * 4) != n_md_bytes) {
        std::cerr << "[" << testlabel
                  << "] internal error: n_beats*4 (" << n_beats * 4
                  << ") != n_md_bytes (" << n_md_bytes << ")\n";
        return 2;
    }

    int cap = (opts.max_vectors > 0
               && opts.max_vectors < (int)vectors.size())
              ? opts.max_vectors : (int)vectors.size();

    if (opts.figure_trace) {
        cap = std::min(cap, 1);
    }

    // Per-failure-class counters (accumulated across BOTH phases).
    int n_hi_only = 0, n_lo_only = 0, n_both_agree_wrong = 0, n_both_diverge = 0;

    // Drive + strict compare for ONE vector. Does NOT reset. Returns pass.
    auto check_vector = [&](int v, const char* phase) -> bool {
        const auto& vec = vectors[v];

        if ((int)vec.md.size() != n_md_bytes) {
            std::cerr << "[FAIL] " << testlabel << " " << phase << " vector " << v
                      << ": MD length " << vec.md.size()
                      << " != expected " << n_md_bytes << "\n";
            return false;
        }

        std::vector<uint64_t> got_beats;
        try {
            drv.setMode(mode);
            drv.pulseStart();
            drv.sendMessageDuetMirror(vec.msg);
            drv.endMsg();
            got_beats = drv.collectBeats(n_beats);
            if (opts.figure_trace) {
                drv.tick(1);
            }
        } catch (const TimeoutError& e) {
            std::cerr << "[FAIL] " << testlabel << " " << phase << " vector " << v
                      << " Len=" << vec.len_bits << " digest timeout: " << e.what() << "\n";
            return false;
        }

        std::reverse(got_beats.begin(), got_beats.end());
        auto exp_beats = mdToDuetBeats(vec.md, n_beats);

        int  first_bad = -1;
        bool any_hi_bad = false, any_lo_bad = false, any_diverge = false;
        for (int i = 0; i < n_beats; i++) {
            if (got_beats[i] != exp_beats[i]) {
                if (first_bad < 0) first_bad = i;
                uint32_t g_hi = uint32_t(got_beats[i] >> 32);
                uint32_t g_lo = uint32_t(got_beats[i] & 0xFFFFFFFFULL);
                uint32_t exp_w = uint32_t(exp_beats[i] & 0xFFFFFFFFULL);
                if (g_hi != exp_w) any_hi_bad = true;
                if (g_lo != exp_w) any_lo_bad = true;
                if (g_hi != g_lo)  any_diverge = true;
            }
        }

        if (first_bad < 0) {
            if (opts.verbosity >= 1) {
                std::cout << "[PASS] " << testlabel << " " << phase << " vector " << v
                          << " Len=" << vec.len_bits
                          << " (both lanes OK across " << n_beats << " beats)\n";
            }
            if (opts.verbosity >= 2) {
                for (int i = 0; i < n_beats; i++) {
                    std::cout << "       beat[" << i << "] = " << hex64(got_beats[i])
                              << "  (hi=" << hex32(uint32_t(got_beats[i] >> 32))
                              << " lo="   << hex32(uint32_t(got_beats[i] & 0xFFFFFFFFULL))
                              << ")\n";
                }
            }
            return true;
        }

        if      ( any_hi_bad && !any_lo_bad)                  n_hi_only++;
        else if (!any_hi_bad &&  any_lo_bad)                  n_lo_only++;
        else if ( any_hi_bad &&  any_lo_bad && !any_diverge)  n_both_agree_wrong++;
        else                                                  n_both_diverge++;

        uint64_t g = got_beats[first_bad];
        uint64_t e = exp_beats[first_bad];
        std::cerr << "[FAIL] " << testlabel << " " << phase
                  << " vector " << v << " Len=" << vec.len_bits
                  << " first-bad-beat=" << first_bad
                  << " (" << describeBeatFailure(g, e) << ")\n"
                  << "       got = " << hex64(g)
                  << "  (hi=" << hex32(uint32_t(g >> 32))
                  << " lo="   << hex32(uint32_t(g & 0xFFFFFFFFULL)) << ")\n"
                  << "       exp = " << hex64(e)
                  << "  (hi=" << hex32(uint32_t(e >> 32))
                  << " lo="   << hex32(uint32_t(e & 0xFFFFFFFFULL)) << ")\n";
        if (opts.verbosity >= 1) {
            std::cerr << "       Msg = " << msgPreview(vec.msg) << "\n"
                      << "       MD  = " << SharmonyDriver::bytesToHex(vec.md) << "\n";
            for (int i = 0; i < n_beats; i++) {
                if (got_beats[i] != exp_beats[i]) {
                    std::cerr << "       beat[" << i << "] got=" << hex64(got_beats[i])
                              << " exp=" << hex64(exp_beats[i])
                              << "  (" << describeBeatFailure(got_beats[i], exp_beats[i]) << ")\n";
                }
            }
        }
        if (opts.verbosity >= 2) {
            std::cerr << "       full beat trace:\n";
            for (int i = 0; i < n_beats; i++) {
                const bool ok = (got_beats[i] == exp_beats[i]);
                std::cerr << "         beat[" << i << "] " << (ok ? "OK  " : "BAD ")
                          << "got=" << hex64(got_beats[i])
                          << "  (hi=" << hex32(uint32_t(got_beats[i] >> 32))
                          << " lo="   << hex32(uint32_t(got_beats[i] & 0xFFFFFFFFULL))
                          << ")\n";
            }
        }
        return false;
    };

    //---------------------------------------------------------------------------------
    //  Phase 1: reset before EVERY vector
    //---------------------------------------------------------------------------------
    std::cout << "[" << testlabel << "] phase 1: reset-per-vector\n";
    int p1_pass = 0, p1_fail = 0;
    for (int v = 0; v < cap; v++) {
        drv.reset();
        if (check_vector(v, "P1")) p1_pass++;
        else {
            p1_fail++;
            if (opts.verbosity == 0 && p1_fail >= 5) {
                std::cerr << "[" << testlabel << "] phase 1 stopping after 5 failures\n";
                break;
            }
        }
    }

    //---------------------------------------------------------------------------------
    //  Phase 2: ONE reset, then chain
    //---------------------------------------------------------------------------------
    int p2_pass = 0, p2_fail = 0;
    if (!opts.figure_trace) {
        std::cout << "[" << testlabel << "] phase 2: single-reset + chain (no per-vector reset)\n";
        drv.reset();
        for (int v = 0; v < cap; v++) {
            if (check_vector(v, "P2")) p2_pass++;
            else {
                p2_fail++;
                if (opts.verbosity == 0 && p2_fail >= 5) {
                    std::cerr << "[" << testlabel << "] phase 2 stopping after 5 failures\n";
                    break;
                }
            }
        }
    } else {
        std::cout << "[" << testlabel << "] figure-trace: skipped phase 2\n";
    }

    std::cout << "[" << testlabel << "] phase 1 (reset/vector): "
              << p1_pass << " pass / " << p1_fail << " fail\n";
    std::cout << "[" << testlabel << "] phase 2 (1 reset+chain): "
              << p2_pass << " pass / " << p2_fail << " fail\n";
    std::cout << "[" << testlabel << "] (cap=" << cap << " run, "
              << vectors.size() << " loaded)\n";
    if (p1_fail > 0 || p2_fail > 0) {
        std::cout << "[" << testlabel << "] failure breakdown (both phases):"
                  << "  hi-only=" << n_hi_only
                  << "  lo-only=" << n_lo_only
                  << "  both-agree=" << n_both_agree_wrong
                  << "  both-diverge=" << n_both_diverge << "\n";
    }

    return (p1_fail == 0 && p2_fail == 0) ? 0 : 1;
}

}  // namespace sharmony
