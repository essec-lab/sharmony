///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Asymmetric duet (x-lane) KAT runner for SHA-224 / SHA-256, two-phase
// (matches HashKatTest):
//   Phase 1  reset() BEFORE every pair.
//   Phase 2  ONE reset(), then all pairs CHAINED (no per-pair reset) - this was
//            the original behavior; it is the stricter phase.
// Builds asymmetric (msg_hi, msg_lo) pairs, drives them on the two lanes, and
// verifies EACH lane's bytes against its expected MD. The test passes only if
// BOTH phases pass every pair.
//
///////////////////////////////////////////////////////////////////////////////////////

#include "HashKatPairDuetTest.hpp"
#include "../../RspParser.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

namespace sharmony {

// Run a single pair: drive, collect, compare each lane. Does NOT reset.
// Returns {hi_pass, lo_pass}.
static std::pair<bool, bool> runOnePair(SharmonyDriver& drv,
                                         const RspVector& vhi,
                                         const RspVector& vlo,
                                         int n_beats,
                                         int n_md_bytes,
                                         int pair_idx,
                                         const std::string& scheme_label,
                                         const std::string& phase,
                                         const std::string& testlabel,
                                         int verbosity,
                                         bool figure_trace)
{
    if ((int)vhi.md.size() != n_md_bytes || (int)vlo.md.size() != n_md_bytes) {
        std::cerr << "[FAIL] " << testlabel << " " << phase << " pair " << pair_idx
                  << ": MD size mismatch (need " << n_md_bytes
                  << " bytes each, got " << vhi.md.size()
                  << " / " << vlo.md.size() << ")\n";
        return {false, false};
    }

    std::vector<uint64_t> got_beats;
    try {
        drv.pulseStart();
        drv.sendMessagesDuet(vhi.msg, vlo.msg);
        drv.endMsg();
        got_beats = drv.collectBeats(n_beats);
        if (figure_trace) {
            drv.tick(1);
        }
    } catch (const TimeoutError& e) {
        std::cerr << "[FAIL] " << testlabel << " " << phase << " pair " << pair_idx
                  << " scheme=" << scheme_label
                  << " hi(LEN=" << vhi.len_bits << ") lo(LEN=" << vlo.len_bits
                  << "): digest timeout: " << e.what() << "\n";
        return {false, false};
    }

    std::reverse(got_beats.begin(), got_beats.end());

    auto got_hi = SharmonyDriver::beatsToHiLaneBytes(got_beats, n_md_bytes);
    auto got_lo = SharmonyDriver::beatsToLoLaneBytes(got_beats, n_md_bytes);

    const bool hi_pass = (got_hi == vhi.md);
    const bool lo_pass = (got_lo == vlo.md);

    if (hi_pass && lo_pass) {
        if (verbosity >= 1) {
            std::cout << "[PASS] " << testlabel << " " << phase << " pair=" << pair_idx
                      << " scheme=" << scheme_label
                      << " hi(LEN=" << vhi.len_bits << ")"
                      << " lo(LEN=" << vlo.len_bits << ")\n";
            std::cout << "       hi MD = " << SharmonyDriver::bytesToHex(got_hi) << "\n"
                      << "       lo MD = " << SharmonyDriver::bytesToHex(got_lo) << "\n";
        }
        if (verbosity >= 2) {
            std::cout << "       full beat trace:\n";
            for (size_t b = 0; b < got_beats.size(); b++) {
                char buf[20];
                std::snprintf(buf, sizeof(buf), "%016lx", (unsigned long)got_beats[b]);
                std::cout << "         beat[" << b << "] = " << buf
                          << "  (hi=" << std::hex
                          << uint32_t(got_beats[b] >> 32) << " lo="
                          << uint32_t(got_beats[b] & 0xFFFFFFFFULL)
                          << std::dec << ")\n";
            }
        }
    } else {
        std::cerr << "[FAIL] " << testlabel << " " << phase << " pair=" << pair_idx
                  << " scheme=" << scheme_label
                  << " hi(LEN=" << vhi.len_bits << "): " << (hi_pass ? "PASS" : "FAIL")
                  << "  lo(LEN=" << vlo.len_bits << "): " << (lo_pass ? "PASS" : "FAIL") << "\n";
        std::cerr << "       hi got = " << SharmonyDriver::bytesToHex(got_hi) << "\n"
                  << "       hi exp = " << SharmonyDriver::bytesToHex(vhi.md) << "\n"
                  << "       lo got = " << SharmonyDriver::bytesToHex(got_lo) << "\n"
                  << "       lo exp = " << SharmonyDriver::bytesToHex(vlo.md) << "\n";
        if (!hi_pass && !lo_pass && got_hi == got_lo) {
            std::cerr << "       [HINT] hi==lo with different inputs - looks like cross-talk\n";
        }
        if (verbosity >= 2) {
            std::cerr << "       full beat trace:\n";
            for (size_t b = 0; b < got_beats.size(); b++) {
                char buf[20];
                std::snprintf(buf, sizeof(buf), "%016lx", (unsigned long)got_beats[b]);
                std::cerr << "         beat[" << b << "] = " << buf << "\n";
            }
        }
    }

    return {hi_pass, lo_pass};
}

int runDuetXLaneKat(SharmonyDriver& drv,
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

    // Drop vectors that would force a 2nd SHA-256 block on a lane (>440 bits);
    // multi-block duet is outside this test's scope.
    vectors.erase(std::remove_if(vectors.begin(), vectors.end(),
                                  [](const RspVector& v) { return v.len_bits > 440; }),
                  vectors.end());

    if ((int)vectors.size() < 2) {
        std::cerr << "[" << testlabel << "] need at least 2 vectors, got "
                  << vectors.size() << "\n";
        return 2;
    }

    std::cout << "[" << testlabel << "] " << vectors.size()
              << " vectors loaded from " << path << "\n";

    const int n_beats    = digestBeatsFor(mode);
    const int n_md_bytes = digestBytesFor(mode);

    //---------------------------------------------------------------------------------
    //  Build the pair list: mid pairs, swap pairs, then the (shortest, longest)
    //  and (longest, shortest) extremes (independent of reset strategy)
    //---------------------------------------------------------------------------------
    struct Pair { int hi; int lo; const char* tag; };
    std::vector<Pair> pairs;
    const int n  = static_cast<int>(vectors.size());
    const int half = n / 2;

    for (int i = 0; i < half; i++) {
        const int hi_idx = i;
        const int lo_idx = half + i;
        if (lo_idx >= n) break;
        pairs.push_back({hi_idx, lo_idx, "mid"});
    }
    for (int i = 0; i < half; i++) pairs.push_back({n - 1 - i, i, "swap"});
    {
        int shortest_idx = 0, longest_idx = 0;
        for (int k = 1; k < n; k++) {
            if (vectors[k].len_bits < vectors[shortest_idx].len_bits) shortest_idx = k;
            if (vectors[k].len_bits > vectors[longest_idx].len_bits)  longest_idx  = k;
        }
        pairs.push_back({shortest_idx, longest_idx, "tgt_short_long"});
        pairs.push_back({longest_idx,  shortest_idx, "tgt_long_short"});
    }

    int cap = static_cast<int>(pairs.size());
    if (opts.max_vectors > 0 && opts.max_vectors < cap) cap = opts.max_vectors;
    if (opts.figure_trace) {
        cap = std::min(cap, 1);
    }

    std::cout << "[" << testlabel << "] running " << cap
              << " pairs (of " << pairs.size() << " built)\n";

    // Run all pairs under a given reset strategy. reset_each_pair=true is Phase 1.
    auto run_phase = [&](const char* phase, bool reset_each_pair,
                         int& pass_pairs, int& fail_pairs,
                         int& checks_pass, int& checks_fail) {
        pass_pairs = fail_pairs = checks_pass = checks_fail = 0;
        if (!reset_each_pair) { drv.reset(); drv.setMode(mode); }  // Phase 2: one reset
        for (int p = 0; p < cap; p++) {
            if (reset_each_pair) { drv.reset(); drv.setMode(mode); }  // Phase 1: per pair
            const auto& pr  = pairs[p];
            const auto& vhi = vectors[pr.hi];
            const auto& vlo = vectors[pr.lo];
            auto [hi_ok, lo_ok] = runOnePair(drv, vhi, vlo, n_beats, n_md_bytes,
                                             p, pr.tag, phase, testlabel, opts.verbosity,
                                             opts.figure_trace);
            if (hi_ok) checks_pass++; else checks_fail++;
            if (lo_ok) checks_pass++; else checks_fail++;
            if (hi_ok && lo_ok) pass_pairs++; else fail_pairs++;
            if (opts.verbosity == 0 && fail_pairs >= 5) {
                std::cerr << "[" << testlabel << "] " << phase
                          << " stopping after 5 failed pairs\n";
                break;
            }
        }
    };

    //---------------------------------------------------------------------------------
    //  Phase 1: reset before every pair
    //---------------------------------------------------------------------------------
    std::cout << "[" << testlabel << "] phase 1: reset-per-pair\n";
    int p1_pp = 0, p1_fp = 0, p1_cp = 0, p1_cf = 0;
    run_phase("P1", /*reset_each_pair=*/true, p1_pp, p1_fp, p1_cp, p1_cf);

    //---------------------------------------------------------------------------------
    //  Phase 2: one reset, then chain
    //---------------------------------------------------------------------------------
    int p2_pp = 0, p2_fp = 0, p2_cp = 0, p2_cf = 0;
    if (!opts.figure_trace) {
        std::cout << "[" << testlabel << "] phase 2: single-reset + chain (no per-pair reset)\n";
        run_phase("P2", /*reset_each_pair=*/false, p2_pp, p2_fp, p2_cp, p2_cf);
    } else {
        std::cout << "[" << testlabel << "] figure-trace: skipped phase 2\n";
    }

    std::cout << "-----------------------------------------------------------------\n";
    std::cout << "[" << testlabel << "] phase 1 (reset/pair): "
              << p1_pp << "/" << (p1_pp + p1_fp) << " pairs PASSED"
              << "  (per-lane: " << p1_cp << " pass / " << p1_cf << " fail)\n";
    std::cout << "[" << testlabel << "] phase 2 (1 reset+chain): "
              << p2_pp << "/" << (p2_pp + p2_fp) << " pairs PASSED"
              << "  (per-lane: " << p2_cp << " pass / " << p2_cf << " fail)\n";

    return (p1_fp == 0 && p2_fp == 0) ? 0 : 1;
}

}  // namespace sharmony
