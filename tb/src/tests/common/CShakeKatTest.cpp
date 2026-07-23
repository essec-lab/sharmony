///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "CShakeKatTest.hpp"
#include "ScenarioCommon.hpp"

#include "../../RspParser.hpp"

#include <iostream>

namespace sharmony {

//-------------------------------------------------------------------------------------
//  NIST SP 800-185 encoding helpers
//-------------------------------------------------------------------------------------

// left_encode(x) for x in 0..255: always produces 2 bytes { 0x01, x }.
static std::vector<uint8_t> left_encode(unsigned x) {
    return {0x01, static_cast<uint8_t>(x)};
}

// encode_string(s) = left_encode(len(s)*8) || s
static std::vector<uint8_t> encode_string(const std::string& s) {
    auto out = left_encode(static_cast<unsigned>(s.size()) * 8);
    for (unsigned char c : s) out.push_back(c);
    return out;
}

// bytepad(X, w) = left_encode(w) || X || zero_pad_to_multiple_of_w
std::vector<uint8_t> cshake_preamble(unsigned rate_bytes,
                                      const std::string& N,
                                      const std::string& S) {
    auto enc_N = encode_string(N);
    auto enc_S = encode_string(S);

    auto out = left_encode(rate_bytes);
    out.insert(out.end(), enc_N.begin(), enc_N.end());
    out.insert(out.end(), enc_S.begin(), enc_S.end());
    while (out.size() % rate_bytes != 0) out.push_back(0x00);
    return out;
}

//-------------------------------------------------------------------------------------
//  Single-vector runner
//-------------------------------------------------------------------------------------
static bool run_one(SharmonyDriver& drv,
                    const TestOptions& opts,
                    Mode mode,
                    unsigned rate_bytes,
                    const CShakeRspVector& v,
                    const std::string& testlabel,
                    const char* phase) {
    const std::string label = "vec" + std::to_string(v.index) +
                              " S=\"" + v.S + "\"";

    // Prepend bytepad preamble to the message.
    auto preamble   = cshake_preamble(rate_bytes, v.N, v.S);
    auto full_input = preamble;
    full_input.insert(full_input.end(), v.msg.begin(), v.msg.end());

    const size_t out_bytes = v.output.size();
    const int    n_beats   = static_cast<int>((out_bytes + 7) / 8);

    std::vector<uint64_t> beats;
    try {
        drv.setMode(mode);
        drv.pulseStart();
        drv.sendMessageNative(full_input);
        drv.endMsg();
        beats = drv.collectBeats(n_beats);
    } catch (const TimeoutError& e) {
        std::cerr << "[FAIL] " << testlabel << " " << phase
                  << " " << label << " timeout: " << e.what() << "\n";
        shakeSqueezeStop(drv);
        return false;
    }

    shakeSqueezeStop(drv);

    auto got = SharmonyDriver::beatsToBytes(beats, out_bytes);
    if (got != v.output) {
        std::cerr << "[FAIL] " << testlabel << " " << phase << " " << label << "\n"
                  << "       exp = " << SharmonyDriver::bytesToHex(v.output) << "\n"
                  << "       got = " << SharmonyDriver::bytesToHex(got) << "\n";
        return false;
    }

    if (opts.verbosity >= 1)
        std::cout << "[PASS] " << testlabel << " " << phase << " " << label << "\n";
    if (opts.verbosity >= 2)
        std::cout << "       out = " << SharmonyDriver::bytesToHex(got) << "\n";

    return true;
}

//-------------------------------------------------------------------------------------
//  Public runner
//-------------------------------------------------------------------------------------
int runCShakeKat(SharmonyDriver& drv,
                 const TestOptions& opts,
                 Mode mode,
                 const std::string& default_rsp,
                 const std::string& testlabel) {
    const std::string path = opts.rsp_path.empty() ? default_rsp : opts.rsp_path;

    std::vector<CShakeRspVector> vectors;
    try {
        vectors = parseRspCShake(path);
    } catch (const RspParseError& e) {
        std::cerr << "[" << testlabel << "] RSP parse error: " << e.what() << "\n";
        return 1;
    }

    // rate_bytes: 168 for cSHAKE128 (1344-bit rate), 136 for cSHAKE256 (1088-bit rate)
    const unsigned rate_bytes = (mode == Mode::CSHAKE128) ? 168u : 136u;

    const int cap = (opts.max_vectors > 0 &&
                     opts.max_vectors < (int)vectors.size())
                    ? opts.max_vectors : (int)vectors.size();

    std::cout << "[" << testlabel << "] " << cap << " of " << vectors.size()
              << " vectors loaded from " << path << "\n";

    int p1_pass = 0, p1_fail = 0;
    int p2_pass = 0, p2_fail = 0;

    std::cout << "[" << testlabel << "] phase 1: reset-per-vector\n";
    for (int i = 0; i < cap; i++) {
        drv.reset();
        if (run_one(drv, opts, mode, rate_bytes, vectors[i], testlabel, "P1"))
            p1_pass++;
        else
            p1_fail++;
    }

    std::cout << "[" << testlabel << "] phase 2: single-reset + chain\n";
    drv.reset();
    for (int i = 0; i < cap; i++) {
        if (run_one(drv, opts, mode, rate_bytes, vectors[i], testlabel, "P2"))
            p2_pass++;
        else
            p2_fail++;
    }

    std::cout << "[" << testlabel << "] phase 1: "
              << p1_pass << " pass / " << p1_fail << " fail\n";
    std::cout << "[" << testlabel << "] phase 2: "
              << p2_pass << " pass / " << p2_fail << " fail\n";

    return (p1_fail == 0 && p2_fail == 0) ? 0 : 1;
}

}  // namespace sharmony
