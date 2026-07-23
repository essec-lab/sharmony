///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "MonteTest.hpp"
#include "../../RspParser.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace sharmony {

// Hash one message through the DUT and return the digest as bytes.
// For SHA-224 / SHA-256 (duet build) the message is driven on both lanes
// in mirror mode. We extract BOTH lanes and require them to agree - if hi
// != lo we throw, which propagates up to main.cpp as a clean FAIL. This
// guarantees Monte catches hi-lane bugs that would otherwise be invisible
// (because the chain would silently consume the correct lo-lane digest).
static std::vector<uint8_t> hashOnce(SharmonyDriver& drv, Mode mode,
                                      const std::vector<uint8_t>& msg) {
    drv.reset();
    drv.setMode(mode);
    drv.pulseStart();

    const bool is_duet_mirror = (mode == Mode::SHA2_224 || mode == Mode::SHA2_256);
    // SHA-2 streams the digest in reverse word order (H7..H0).
    const bool is_sha2 = is_duet_mirror ||
        mode == Mode::SHA2_384 || mode == Mode::SHA2_512 ||
        mode == Mode::SHA2_512_224 || mode == Mode::SHA2_512_256;
    const size_t md_len = digestBytesFor(mode);

    if (is_duet_mirror) {
        drv.sendMessageDuetMirror(msg);
        drv.endMsg();
        auto beats = drv.collectBeats(digestBeatsFor(mode));
        if (is_sha2) std::reverse(beats.begin(), beats.end());
        auto lo = SharmonyDriver::beatsToLoLaneBytes(beats, md_len);
        auto hi = SharmonyDriver::beatsToHiLaneBytes(beats, md_len);
        if (lo != hi) {
            throw std::runtime_error(
                "duet lane divergence (hi != lo) on mirrored stimulus. "
                "lo=" + SharmonyDriver::bytesToHex(lo) +
                " hi=" + SharmonyDriver::bytesToHex(hi));
        }
        return lo;
    } else {
        drv.sendMessageNative(msg);
        drv.endMsg();
        auto beats = drv.collectBeats(digestBeatsFor(mode));
        if (is_sha2) std::reverse(beats.begin(), beats.end());
        return SharmonyDriver::beatsToBytes(beats, md_len);
    }
}

// SHA-2 Monte: 3-message sliding window per the NIST SHAVS MCT.
//   MD[-3] = MD[-2] = MD[-1] = Seed
//   for j in 0..99:
//     for i in 0..999:
//       MD[i] = SHA(MD[i-3] || MD[i-2] || MD[i-1])
//     checkpoint_j = MD[999]
//     MD[-3] = MD[-2] = MD[-1] = MD[999]
static int runSha2Monte(SharmonyDriver& drv,
                         const TestOptions& opts,
                         Mode mode,
                         const RspMonteFile& monte,
                         const std::string& testlabel) {
    const size_t md_len = digestBytesFor(mode);
    if (monte.seed.size() != md_len) {
        std::cerr << "[" << testlabel << "] seed size " << monte.seed.size()
                  << " != digest size " << md_len << "\n";
        return 2;
    }

    std::vector<uint8_t> mdm3 = monte.seed;
    std::vector<uint8_t> mdm2 = monte.seed;
    std::vector<uint8_t> mdm1 = monte.seed;

    int n_checkpoints = static_cast<int>(monte.checkpoints.size());
    if (opts.max_vectors > 0 && opts.max_vectors < n_checkpoints)
        n_checkpoints = opts.max_vectors;

    int n_pass = 0, n_fail = 0;

    for (int j = 0; j < n_checkpoints; j++) {
        for (int i = 0; i < 1000; i++) {
            std::vector<uint8_t> m;
            m.reserve(3 * md_len);
            m.insert(m.end(), mdm3.begin(), mdm3.end());
            m.insert(m.end(), mdm2.begin(), mdm2.end());
            m.insert(m.end(), mdm1.begin(), mdm1.end());
            auto md = hashOnce(drv, mode, m);
            mdm3 = mdm2;
            mdm2 = mdm1;
            mdm1 = md;
            if (opts.verbosity >= 2 && (i + 1) % 100 == 0) {
                std::cout << "       [progress] checkpoint=" << j
                          << " inner=" << (i + 1) << "/1000"
                          << " MD=" << SharmonyDriver::bytesToHex(mdm1).substr(0, 32)
                          << "...\n";
            }
        }
        const auto& expected = monte.checkpoints[j];
        if (mdm1 != expected) {
            std::cerr << "[FAIL] " << testlabel << " checkpoint " << j << "\n"
                      << "       exp = " << SharmonyDriver::bytesToHex(expected) << "\n"
                      << "       got = " << SharmonyDriver::bytesToHex(mdm1) << "\n";
            n_fail++;
            if (opts.verbosity == 0 && n_fail >= 3) {
                std::cerr << "[" << testlabel << "] stopping after 3 failures\n";
                break;
            }
        } else {
            n_pass++;
            if (opts.verbosity >= 1)
                std::cout << "[PASS] " << testlabel << " checkpoint " << j << "\n";
        }
        // Reseed for the next checkpoint window: MD[-3..-1] = MD[999].
        mdm3 = mdm1;
        mdm2 = mdm1;
    }

    std::cout << "[" << testlabel << "] " << n_pass << " pass / "
              << n_fail << " fail (out of " << n_checkpoints
              << " checkpoints)\n";
    return (n_fail == 0) ? 0 : 1;
}

// SHA-3 Monte: simple chain.
//   MD = Seed
//   for j in 0..99:
//     for i in 1..1000:
//       MD = SHA3(MD)
//     checkpoint_j = MD
static int runSha3Monte(SharmonyDriver& drv,
                         const TestOptions& opts,
                         Mode mode,
                         const RspMonteFile& monte,
                         const std::string& testlabel) {
    const size_t md_len = digestBytesFor(mode);
    std::vector<uint8_t> md = monte.seed;
    if (md.size() != md_len) {
        std::cerr << "[" << testlabel << "] seed size " << md.size()
                  << " != digest size " << md_len << "\n";
        return 2;
    }

    int n_checkpoints = static_cast<int>(monte.checkpoints.size());
    if (opts.max_vectors > 0 && opts.max_vectors < n_checkpoints)
        n_checkpoints = opts.max_vectors;

    int n_pass = 0, n_fail = 0;

    for (int j = 0; j < n_checkpoints; j++) {
        for (int i = 0; i < 1000; i++) {
            md = hashOnce(drv, mode, md);
            if (opts.verbosity >= 2 && (i + 1) % 100 == 0) {
                std::cout << "       [progress] checkpoint=" << j
                          << " inner=" << (i + 1) << "/1000"
                          << " MD=" << SharmonyDriver::bytesToHex(md).substr(0, 32)
                          << "...\n";
            }
        }
        const auto& expected = monte.checkpoints[j];
        if (md != expected) {
            std::cerr << "[FAIL] " << testlabel << " checkpoint " << j << "\n"
                      << "       exp = " << SharmonyDriver::bytesToHex(expected) << "\n"
                      << "       got = " << SharmonyDriver::bytesToHex(md) << "\n";
            n_fail++;
            if (opts.verbosity == 0 && n_fail >= 3) {
                std::cerr << "[" << testlabel << "] stopping after 3 failures\n";
                break;
            }
        } else {
            n_pass++;
            if (opts.verbosity >= 1)
                std::cout << "[PASS] " << testlabel << " checkpoint " << j << "\n";
        }
    }

    std::cout << "[" << testlabel << "] " << n_pass << " pass / "
              << n_fail << " fail (out of " << n_checkpoints
              << " checkpoints)\n";
    return (n_fail == 0) ? 0 : 1;
}

int runMonte(SharmonyDriver& drv,
             const TestOptions& opts,
             Mode mode,
             MonteFamily family,
             const std::string& default_rsp,
             const std::string& testlabel) {
    const std::string path = opts.rsp_path.empty() ? default_rsp : opts.rsp_path;

    RspMonteFile monte;
    try {
        monte = parseRspMonte(path);
    } catch (const RspParseError& e) {
        std::cerr << "[" << testlabel << "] Monte RSP parse error: "
                  << e.what() << "\n";
        return 2;
    }

    std::cout << "[" << testlabel << "] seed=" << monte.seed.size()
              << " bytes, " << monte.checkpoints.size()
              << " checkpoints loaded from " << path
              << " (Monte Carlo, this will take a while)\n";

    return (family == MonteFamily::Sha2)
        ? runSha2Monte(drv, opts, mode, monte, testlabel)
        : runSha3Monte(drv, opts, mode, monte, testlabel);
}

}  // namespace sharmony
