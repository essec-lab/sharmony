///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Two-phase KAT runner:
//   Phase 1  reset() BEFORE every vector (each vector starts from cold reset).
//   Phase 2  ONE reset() at vector 0, then all vectors run CHAINED with no
//            per-vector reset - each relies on the DUT returning to idle on its
//            own (pulseStart waits for !busy) between vectors.
// A test passes only if BOTH phases pass for every vector. Phase 2 is the
// stricter one: it proves the engine cleanly returns to idle and accepts a new
// transaction without a reset to bail it out.
//
// Note: this runner is for the finite-output hash modes (SHA-2 / SHA-3). It is
// not used for SHAKE/XOF (those never self-terminate without out_ready low and
// have their own runners), so Phase-2 chaining is safe here.
//
///////////////////////////////////////////////////////////////////////////////////////

#include "HashKatTest.hpp"
#include "../../RspParser.hpp"

#include <algorithm>
#include <iostream>
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

static bool isSha2Mode(Mode m) {
    return m == Mode::SHA2_224 || m == Mode::SHA2_256 ||
           m == Mode::SHA2_384 || m == Mode::SHA2_512 ||
           m == Mode::SHA2_512_224 || m == Mode::SHA2_512_256;
}

int runHashKat(SharmonyDriver& drv,
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
              << " vectors loaded from " << path << "\n";

    const int n_beats    = digestBeatsFor(mode);
    const int n_md_bytes = digestBytesFor(mode);
          int cap = (opts.max_vectors > 0
            && opts.max_vectors < (int)vectors.size())
            ? opts.max_vectors : (int)vectors.size();

    if (opts.figure_trace) {
        cap = std::min(cap, 1);
    }

    // Run ONE vector and compare. Does NOT reset (the caller decides resets).
    // Returns true on pass. All driver calls are guarded so a stuck DUT in the
    // chained phase reports a clean FAIL instead of propagating out.
    auto check_vector = [&](int v, const char* phase) -> bool {
        const auto& vec = vectors[v];

        std::vector<uint64_t> beats;
        try {
            drv.setMode(mode);
            drv.pulseStart();
            drv.sendMessageNative(vec.msg);
            drv.endMsg();
            beats = drv.collectBeats(n_beats);
            if (opts.figure_trace) {
                drv.tick(2);
            }
        } catch (const TimeoutError& e) {
            std::cerr << "[FAIL] " << testlabel << " " << phase
                      << " vector " << v << " Len=" << vec.len_bits
                      << " timeout: " << e.what() << "\n";
            return false;
        }

        // All SHA-2 modes stream the digest in reverse word order (H7..H0).
        if (isSha2Mode(mode)) std::reverse(beats.begin(), beats.end());

        auto got = SharmonyDriver::beatsToBytes(beats, n_md_bytes);

        if (got != vec.md) {
            std::cerr << "[FAIL] " << testlabel << " " << phase
                      << " vector " << v << " Len=" << vec.len_bits
                      << " Msg=" << msgPreview(vec.msg) << "\n"
                      << "       exp = " << SharmonyDriver::bytesToHex(vec.md) << "\n"
                      << "       got = " << SharmonyDriver::bytesToHex(got) << "\n";
            return false;
        }

        if (opts.verbosity >= 1) {
            std::cout << "[PASS] " << testlabel << " " << phase
                      << " vector " << v << " Len=" << vec.len_bits << "\n";
        }
        if (opts.verbosity >= 2) {
            std::cout << "       Msg = " << msgPreview(vec.msg) << "\n"
                      << "       MD  = " << SharmonyDriver::bytesToHex(got) << "\n";
            for (size_t b = 0; b < beats.size(); b++) {
                char buf[20];
                std::snprintf(buf, sizeof(buf), "%016lx", (unsigned long)beats[b]);
                std::cout << "       beat[" << b << "] = " << buf << "\n";
            }
        }
        return true;
    };

    //---------------------------------------------------------------------------------
    //  Phase 1: reset before EVERY vector
    //---------------------------------------------------------------------------------
    std::cout << "[" << testlabel << "] phase 1: reset-per-vector\n";
    int p1_pass = 0, p1_fail = 0;
    for (int v = 0; v < cap; v++) {
        drv.reset();
        if (check_vector(v, "P1")) {
            p1_pass++;
        } else {
            p1_fail++;
            if (opts.verbosity == 0 && p1_fail >= 5) {
                std::cerr << "[" << testlabel << "] phase 1 stopping after 5 failures\n";
                break;
            }
        }
    }

    //---------------------------------------------------------------------------------
    //  Phase 2: ONE reset at vector 0, then chain (no per-vector reset)
    //---------------------------------------------------------------------------------
    int p2_pass = 0, p2_fail = 0;

    if (!opts.figure_trace) {
        std::cout << "[" << testlabel << "] phase 2: single-reset + chain (no per-vector reset)\n";
        drv.reset();

        for (int v = 0; v < cap; v++) {
            if (check_vector(v, "P2")) {
                p2_pass++;
            } else {
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

    return (p1_fail == 0 && p2_fail == 0) ? 0 : 1;
}

}  // namespace sharmony
