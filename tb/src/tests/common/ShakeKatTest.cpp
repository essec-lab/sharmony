///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Two-phase SHAKE KAT runner (matches HashKatTest):
//   Phase 1  reset() BEFORE every vector.
//   Phase 2  ONE reset(), then all vectors CHAINED with no per-vector reset.
//
// SHAKE/XOF wrinkle: the engine never stops squeezing on its own - it keeps
// emitting until out_ready drops at a clock edge while in CORE_OUTPUT_XOF. So
// after collecting our 16-byte prefix we MUST actively stop the squeeze and
// clock the core back to IDLE; otherwise Phase 2's next pulseStart() would wait
// on a forever-busy engine. shakeSqueezeStop() does that. (Phase 1's per-vector
// reset would also stop it, but running the stop in both phases keeps the
// per-vector path uniform and harmless.)
//
///////////////////////////////////////////////////////////////////////////////////////

#include "ShakeKatTest.hpp"
#include "ScenarioCommon.hpp"
#include "../../RspParser.hpp"

#include <iostream>
#include <vector>

namespace sharmony {

int runShakeKat(SharmonyDriver& drv,
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

    // Starter constraint: only check first 16 bytes (2 beats) of XOF stream.
    const int n_beats     = digestBeatsFor(mode);   // 2
    const int compare_len = digestBytesFor(mode);   // 16

    const int cap = (opts.max_vectors > 0
                     && opts.max_vectors < (int)vectors.size())
                    ? opts.max_vectors : (int)vectors.size();

    // Drive + compare ONE vector. Does NOT reset. Always stops the squeeze so
    // the engine is left IDLE for the next vector. Returns 1 pass, 0 fail,
    // -1 skip (short-Output vector).
    auto check_vector = [&](int v, const char* phase) -> int {
        const auto& vec = vectors[v];

        // Some SHAKE .rsp files contain short-Output vectors ([Outputlen=16]).
        // Skip those - comparing a truncated expected to our 16-byte prefix
        // would false-fail. (No driving, so nothing to stop.)
        if ((int)vec.md.size() < compare_len) {
            if (opts.verbosity >= 1) {
                std::cout << "[SKIP] " << testlabel << " " << phase << " vector " << v
                          << " Outputlen=" << (vec.md.size() * 8) << " < "
                          << (compare_len * 8) << "\n";
            }
            return -1;
        }

        std::vector<uint64_t> beats;
        try {
            drv.setMode(mode);
            drv.pulseStart();
            drv.sendMessageNative(vec.msg);
            drv.endMsg();
            beats = drv.collectBeats(n_beats);
        } catch (const TimeoutError& e) {
            std::cerr << "[FAIL] " << testlabel << " " << phase << " vector " << v
                      << " Len=" << vec.len_bits << " timeout: " << e.what() << "\n";
            shakeSqueezeStop(drv);   // best-effort: leave the engine idle
            return 0;
        }

        shakeSqueezeStop(drv);       // stop the XOF -> IDLE for the next vector

        auto got = SharmonyDriver::beatsToBytes(beats, compare_len);
        std::vector<uint8_t> exp_head(vec.md.begin(), vec.md.begin() + compare_len);

        if (got != exp_head) {
            std::cerr << "[FAIL] " << testlabel << " " << phase
                      << " vector " << v << " Len=" << vec.len_bits << "\n"
                      << "       exp[0..16] = " << SharmonyDriver::bytesToHex(exp_head) << "\n"
                      << "       got        = " << SharmonyDriver::bytesToHex(got) << "\n";
            return 0;
        }

        if (opts.verbosity >= 1) {
            std::cout << "[PASS] " << testlabel << " " << phase
                      << " vector " << v << " Len=" << vec.len_bits << "\n";
        }
        if (opts.verbosity >= 2) {
            std::cout << "       Output[0..16] = " << SharmonyDriver::bytesToHex(got) << "\n";
            for (size_t b = 0; b < beats.size(); b++) {
                char buf[20];
                std::snprintf(buf, sizeof(buf), "%016lx", (unsigned long)beats[b]);
                std::cout << "       beat[" << b << "] = " << buf << "\n";
            }
        }
        return 1;
    };

    auto run_phase = [&](const char* phase, bool reset_each,
                         int& pass, int& fail, int& skip) {
        pass = fail = skip = 0;
        if (!reset_each) drv.reset();          // Phase 2: the single reset
        for (int v = 0; v < cap; v++) {
            if (reset_each) drv.reset();        // Phase 1: per vector
            int r = check_vector(v, phase);
            if      (r == 1)  pass++;
            else if (r == -1) skip++;
            else {
                fail++;
                if (opts.verbosity == 0 && fail >= 5) {
                    std::cerr << "[" << testlabel << "] " << phase
                              << " stopping after 5 failures\n";
                    break;
                }
            }
        }
    };

    std::cout << "[" << testlabel << "] phase 1: reset-per-vector\n";
    int p1_pass = 0, p1_fail = 0, p1_skip = 0;
    run_phase("P1", /*reset_each=*/true, p1_pass, p1_fail, p1_skip);

    std::cout << "[" << testlabel << "] phase 2: single-reset + chain (no per-vector reset)\n";
    int p2_pass = 0, p2_fail = 0, p2_skip = 0;
    run_phase("P2", /*reset_each=*/false, p2_pass, p2_fail, p2_skip);

    std::cout << "[" << testlabel << "] phase 1 (reset/vector): "
              << p1_pass << " pass / " << p1_fail << " fail / " << p1_skip << " skip\n";
    std::cout << "[" << testlabel << "] phase 2 (1 reset+chain): "
              << p2_pass << " pass / " << p2_fail << " fail / " << p2_skip << " skip\n";
    std::cout << "[" << testlabel << "] (cap=" << cap << " run, "
              << vectors.size() << " loaded)\n";

    return (p1_fail == 0 && p2_fail == 0) ? 0 : 1;
}

}  // namespace sharmony
