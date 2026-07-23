///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "ShakeXofTest.hpp"
#include "ScenarioCommon.hpp"

#include <cctype>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace sharmony {

//-------------------------------------------------------------------------------------
//  Local helpers (kept self-contained so RspParser is untouched).
//-------------------------------------------------------------------------------------
namespace {

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) a++;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;
    return s.substr(a, b - a);
}

// Return the value after '=' (trimmed), or "" if no '='.
std::string valueAfterEq(const std::string& line) {
    auto pos = line.find('=');
    if (pos == std::string::npos) return "";
    return trim(line.substr(pos + 1));
}

bool keyIs(const std::string& line, const char* key) {
    // key is the token before '='; compare case-insensitively.
    auto pos = line.find('=');
    std::string k = trim(pos == std::string::npos ? line : line.substr(0, pos));
    std::string want(key);
    if (k.size() != want.size()) return false;
    for (size_t i = 0; i < k.size(); i++)
        if (std::tolower((unsigned char)k[i]) != std::tolower((unsigned char)want[i]))
            return false;
    return true;
}

std::vector<uint8_t> hexToBytes(const std::string& hex_in) {
    std::string hex = trim(hex_in);
    std::vector<uint8_t> out;
    if (hex.size() % 2 != 0) return out;            // caller treats empty as error
    out.reserve(hex.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

// One SHAKE transaction on the DUT: (optionally reset) -> start -> drive msg ->
// squeeze out_bytes. Returns the squeezed bytes.
//   reset_first=true  : reset() first (cold start; stops any prior squeeze).
//                       Used by Monte and by VariableOut phase 1.
//   reset_first=false : no reset; relies on the engine already being IDLE, and
//                       stops the squeeze at the end so the NEXT chained call
//                       starts from IDLE. Used by VariableOut phase 2.
std::vector<uint8_t> shakeOnce(SharmonyDriver& drv, Mode mode,
                               const std::vector<uint8_t>& msg,
                               size_t out_bytes,
                               bool reset_first = true) {
    if (reset_first) drv.reset();
    drv.setMode(mode);
    drv.pulseStart();
    drv.sendMessageNative(msg);
    drv.endMsg();
    auto out = squeezeBytes(drv, out_bytes);
    if (!reset_first) shakeSqueezeStop(drv);   // leave engine IDLE for the next call
    return out;
}

}  // namespace

//-------------------------------------------------------------------------------------
//  Public: squeeze exactly nBytes from the streaming XOF output.
//-------------------------------------------------------------------------------------
std::vector<uint8_t> squeezeBytes(SharmonyDriver& drv, size_t nBytes,
                                  unsigned timeoutPerBeat) {
    const size_t n_beats = (nBytes + 7) / 8;        // ceil to 64-bit beats
    auto beats = drv.collectBeats(n_beats, timeoutPerBeat);
    return SharmonyDriver::beatsToBytes(beats, nBytes);   // MSB-first, truncates
}

//-------------------------------------------------------------------------------------
//  SHAKE VariableOut
//-------------------------------------------------------------------------------------
int runShakeVariableOut(SharmonyDriver& drv, const TestOptions& opts,
                        Mode mode, const std::string& default_rsp,
                        const std::string& testlabel) {
    const std::string path = opts.rsp_path.empty() ? default_rsp : opts.rsp_path;
    std::ifstream f(path);
    if (!f) {
        std::cerr << "[" << testlabel << "] cannot open RSP '" << path << "'\n";
        return 2;
    }

    struct Vec { int out_bits; std::vector<uint8_t> msg, out; };
    std::vector<Vec> vectors;

    std::string line;
    int   cur_outlen = -1;
    bool  have_outlen = false, have_msg = false;
    std::vector<uint8_t> cur_msg;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == '[') continue;
        if (keyIs(line, "Outputlen")) {
            cur_outlen = std::stoi(valueAfterEq(line));
            have_outlen = true; have_msg = false;
        } else if (keyIs(line, "Msg")) {
            cur_msg = hexToBytes(valueAfterEq(line));
            have_msg = true;
        } else if (keyIs(line, "Output")) {
            auto out = hexToBytes(valueAfterEq(line));
            if (have_outlen && have_msg)
                vectors.push_back({cur_outlen, cur_msg, out});
            have_outlen = have_msg = false;
        }
        // COUNT lines are ignored (index is implicit).
    }

    if (vectors.empty()) {
        std::cerr << "[" << testlabel << "] no vectors parsed from " << path << "\n";
        return 2;
    }

    //---------------------------------------------------------------------------------
    //  Figure mode (spec timing-diagram capture)
    //---------------------------------------------------------------------------------
    // When invoked with --figure-trace, emit ONE clean XOF transaction
    // chosen to CROSS the sponge rate (so a second Keccak permutation runs
    // mid-squeeze), and STOP the squeeze by deasserting output_ready instead of
    // resetting -- demonstrating that the consumer decides the output length.
    // Reuses the same parser + squeezeBytes as the regression path.
    if (opts.figure_trace) {
        // Pick the first byte-aligned vector whose output crosses the rate
        // (>= 1280 bits => 20 beats for SHAKE256's 17-beat rate); else longest.
        const int kCrossBits = 1280;
        int sel = -1;
        for (int i = 0; i < (int)vectors.size(); ++i) {
            if (vectors[i].out_bits % 8 == 0 && vectors[i].out_bits >= kCrossBits) {
                sel = i; break;
            }
        }
        if (sel < 0) {
            for (int i = 0; i < (int)vectors.size(); ++i)
                if (vectors[i].out_bits % 8 == 0 &&
                    (sel < 0 || vectors[i].out_bits > vectors[sel].out_bits))
                    sel = i;
        }
        if (sel < 0) {
            std::cerr << "[" << testlabel << "] figure: no byte-aligned vector\n";
            return 2;
        }
        const auto& v = vectors[sel];
        const size_t out_bytes = v.out_bits / 8;
        std::cout << "[" << testlabel << "] figure mode: vec=" << sel
                  << " Outputlen=" << v.out_bits << " bits (" << out_bytes
                  << " bytes, " << (out_bytes + 7) / 8 << " beats)\n";

        drv.reset();
        drv.setMode(mode);
        drv.setOutReady(true);
        drv.pulseStart();
        drv.sendMessageNative(v.msg);
        drv.endMsg();

        std::vector<uint8_t> got;
        try {
            got = squeezeBytes(drv, out_bytes);
        } catch (const TimeoutError& e) {
            std::cerr << "[FAIL] " << testlabel << " figure: " << e.what() << "\n";
            shakeSqueezeStop(drv);
            return 1;
        }
        // Consumer-controlled stop: deassert output_ready, clock back to IDLE.
        shakeSqueezeStop(drv);

        const bool ok = (got == v.out);
        if (ok) {
            std::cout << "[PASS] " << testlabel << " figure (Outputlen="
                      << v.out_bits << ")\n";
        } else {
            std::cerr << "[FAIL] " << testlabel << " figure (Outputlen="
                      << v.out_bits << ")\n"
                      << "       exp = " << SharmonyDriver::bytesToHex(v.out) << "\n"
                      << "       got = " << SharmonyDriver::bytesToHex(got) << "\n";
        }
        return ok ? 0 : 1;
    }

    int cap = static_cast<int>(vectors.size());
    if (opts.max_vectors > 0 && opts.max_vectors < cap) cap = opts.max_vectors;
    std::cout << "[" << testlabel << "] " << vectors.size()
              << " vectors from " << path << " (running " << cap << ")\n";

    // Drive + compare ONE vector. reset_first selects cold-start vs chained.
    auto check_one = [&](int i, const char* phase, bool reset_first) -> bool {
        const auto& v = vectors[i];
        if (v.out_bits % 8 != 0) {        // CAVS byte-oriented files are 8-aligned
            std::cerr << "[FAIL] " << testlabel << " " << phase << " vec=" << i
                      << " Outputlen=" << v.out_bits << " not byte-aligned\n";
            return false;
        }
        const size_t out_bytes = v.out_bits / 8;

        std::vector<uint8_t> got;
        try {
            got = shakeOnce(drv, mode, v.msg, out_bytes, reset_first);
        } catch (const TimeoutError& e) {
            std::cerr << "[FAIL] " << testlabel << " " << phase << " vec=" << i
                      << " Outputlen=" << v.out_bits << ": " << e.what() << "\n";
            if (!reset_first) shakeSqueezeStop(drv);
            return false;
        }

        if (got == v.out) {
            if (opts.verbosity >= 1)
                std::cout << "[PASS] " << testlabel << " " << phase << " vec=" << i
                          << " Outputlen=" << v.out_bits << "\n";
            return true;
        }
        std::cerr << "[FAIL] " << testlabel << " " << phase << " vec=" << i
                  << " Outputlen=" << v.out_bits << "\n"
                  << "       exp = " << SharmonyDriver::bytesToHex(v.out) << "\n"
                  << "       got = " << SharmonyDriver::bytesToHex(got) << "\n";
        return false;
    };

    auto run_phase = [&](const char* phase, bool reset_each, int& pass, int& fail) {
        pass = fail = 0;
        if (!reset_each) drv.reset();          // phase 2: the single reset
        for (int i = 0; i < cap; i++) {
            if (check_one(i, phase, /*reset_first=*/reset_each)) pass++;
            else {
                fail++;
                if (opts.verbosity == 0 && fail >= 5) {
                    std::cerr << "[" << testlabel << "] " << phase
                              << " stopping after 5 fails\n";
                    break;
                }
            }
        }
    };

    std::cout << "[" << testlabel << "] phase 1: reset-per-vector\n";
    int p1_pass = 0, p1_fail = 0;
    run_phase("P1", /*reset_each=*/true, p1_pass, p1_fail);

    std::cout << "[" << testlabel << "] phase 2: single-reset + chain (no per-vector reset)\n";
    int p2_pass = 0, p2_fail = 0;
    run_phase("P2", /*reset_each=*/false, p2_pass, p2_fail);

    std::cout << "[" << testlabel << "] phase 1 (reset/vector): "
              << p1_pass << " pass / " << p1_fail << " fail\n";
    std::cout << "[" << testlabel << "] phase 2 (1 reset+chain): "
              << p2_pass << " pass / " << p2_fail << " fail\n";
    return (p1_fail == 0 && p2_fail == 0) ? 0 : 1;
}

//-------------------------------------------------------------------------------------
//  SHAKE Monte-Carlo
//-------------------------------------------------------------------------------------
int runShakeMonte(SharmonyDriver& drv, const TestOptions& opts,
                  Mode mode, const std::string& default_rsp,
                  const std::string& testlabel) {
    const std::string path = opts.rsp_path.empty() ? default_rsp : opts.rsp_path;
    std::ifstream f(path);
    if (!f) {
        std::cerr << "[" << testlabel << "] cannot open RSP '" << path << "'\n";
        return 2;
    }

    int min_bits = -1, max_bits = -1;
    std::vector<uint8_t> seed;
    struct Ck { int out_bits; std::vector<uint8_t> out; };
    std::vector<Ck> checkpoints;

    std::string line;
    bool have_outlen = false;
    int  cur_outlen = -1;
    while (std::getline(f, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        if (t[0] == '[') {
            // header parameters
            auto eq = t.find('=');
            if (eq != std::string::npos) {
                std::string val = trim(t.substr(eq + 1));
                if (!val.empty() && val.back() == ']') val.pop_back();
                val = trim(val);
                if (t.find("Minimum Output Length") != std::string::npos)
                    min_bits = std::stoi(val);
                else if (t.find("Maximum Output Length") != std::string::npos)
                    max_bits = std::stoi(val);
            }
            continue;
        }
        if (keyIs(t, "Msg")) {
            seed = hexToBytes(valueAfterEq(t));        // the one-time seed
        } else if (keyIs(t, "Outputlen")) {
            cur_outlen = std::stoi(valueAfterEq(t));
            have_outlen = true;
        } else if (keyIs(t, "Output")) {
            auto out = hexToBytes(valueAfterEq(t));
            if (have_outlen) checkpoints.push_back({cur_outlen, out});
            have_outlen = false;
        }
        // COUNT ignored (index implicit).
    }

    if (seed.empty() || checkpoints.empty() || min_bits < 0 || max_bits < 0) {
        std::cerr << "[" << testlabel << "] malformed Monte RSP (seed/min/max/checkpoints)\n";
        return 2;
    }

    const size_t minB = static_cast<size_t>(min_bits) / 8;
    const size_t maxB = static_cast<size_t>(max_bits) / 8;
    const size_t range = maxB - minB + 1;

    int cap = static_cast<int>(checkpoints.size());
    if (opts.max_vectors > 0 && opts.max_vectors < cap) cap = opts.max_vectors;

    std::cout << "[" << testlabel << "] Monte: seed=" << SharmonyDriver::bytesToHex(seed)
              << "  minOut=" << minB << "B maxOut=" << maxB << "B"
              << "  checkpoints=" << checkpoints.size()
              << " (running " << cap << ")\n";

    //---------------------------------------------------------------------------------
    //  the Monte-Carlo loop (algorithm verified vs NIST vectors)
    //---------------------------------------------------------------------------------
    std::vector<uint8_t> out = seed;
    size_t outlen = maxB;                    // initial squeeze length (bytes)
    int n_pass = 0, n_fail = 0;

    for (int j = 0; j < cap; j++) {
        for (int i = 0; i < 1000; i++) {
            // leftmost 128 bits of `out`, zero-padded to 16 bytes
            std::vector<uint8_t> msg16(16, 0);
            for (size_t k = 0; k < 16 && k < out.size(); k++) msg16[k] = out[k];

            try {
                out = shakeOnce(drv, mode, msg16, outlen);
            } catch (const TimeoutError& e) {
                std::cerr << "[FAIL] " << testlabel << " checkpoint=" << j
                          << " inner i=" << i << ": " << e.what() << "\n";
                n_fail++;
                goto next_checkpoint;        // abandon this checkpoint
            }

            // next outlen from the rightmost 16 bits (big-endian) of `out`
            {
                const size_t L = out.size();
                const unsigned rm16 = (static_cast<unsigned>(out[L - 2]) << 8)
                                    |  static_cast<unsigned>(out[L - 1]);
                outlen = minB + (rm16 % range);
            }
        }

        // checkpoint compare: both length and bytes must match
        {
            const auto& ck = checkpoints[j];
            const bool len_ok = (static_cast<int>(out.size()) * 8 == ck.out_bits);
            const bool out_ok = (out == ck.out);
            if (len_ok && out_ok) {
                n_pass++;
                if (opts.verbosity >= 1)
                    std::cout << "[PASS] " << testlabel << " checkpoint=" << j
                              << " Outputlen=" << ck.out_bits << "\n";
            } else {
                n_fail++;
                std::cerr << "[FAIL] " << testlabel << " checkpoint=" << j << "\n"
                          << "       exp len/out = " << ck.out_bits << "b / "
                          << SharmonyDriver::bytesToHex(ck.out) << "\n"
                          << "       got len/out = " << (out.size() * 8) << "b / "
                          << SharmonyDriver::bytesToHex(out) << "\n";
                if (opts.verbosity == 0) {
                    std::cerr << "[" << testlabel
                              << "] stopping at first failed checkpoint\n";
                    break;
                }
            }
        }
        next_checkpoint:;
    }

    std::cout << "[" << testlabel << "] Summary: " << n_pass << " pass / "
              << n_fail << " fail\n";
    return (n_fail == 0) ? 0 : 1;
}

}  // namespace sharmony
