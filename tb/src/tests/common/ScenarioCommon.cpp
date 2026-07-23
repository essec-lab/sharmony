///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "ScenarioCommon.hpp"
#include "../../RspParser.hpp"   // hexToBytes

#include <algorithm>
#include <iostream>
#include <map>
#include <string>

namespace sharmony {

const std::vector<Mode> kAllModes = {
    Mode::SHA2_224,
    Mode::SHA2_256,
    Mode::SHA2_384,
    Mode::SHA2_512,
    Mode::SHA2_512_224,
    Mode::SHA2_512_256,
    Mode::SHA3_224,
    Mode::SHA3_256,
    Mode::SHA3_384,
    Mode::SHA3_512,
    Mode::SHAKE128,
    Mode::SHAKE256,
};

bool modeFromName(const std::string& name, Mode& out) {
    static const std::map<std::string, Mode> kByName = {
        {"HASH_SHA2_224",     Mode::SHA2_224},
        {"HASH_SHA2_256",     Mode::SHA2_256},
        {"HASH_SHA2_384",     Mode::SHA2_384},
        {"HASH_SHA2_512",     Mode::SHA2_512},
        {"HASH_SHA2_512_224", Mode::SHA2_512_224},
        {"HASH_SHA2_512_256", Mode::SHA2_512_256},
        {"HASH_SHA3_224",     Mode::SHA3_224},
        {"HASH_SHA3_256",     Mode::SHA3_256},
        {"HASH_SHA3_384",     Mode::SHA3_384},
        {"HASH_SHA3_512",     Mode::SHA3_512},
        {"XOF_SHAKE128",      Mode::SHAKE128},
        {"XOF_SHAKE256",      Mode::SHAKE256},
    };
    auto it = kByName.find(name);
    if (it == kByName.end()) return false;
    out = it->second;
    return true;
}

bool modeIsSha2(Mode m) {
    switch (m) {
        case Mode::SHA2_224: case Mode::SHA2_256: case Mode::SHA2_384:
        case Mode::SHA2_512: case Mode::SHA2_512_224: case Mode::SHA2_512_256:
            return true;
        default: return false;
    }
}
bool modeIsSha3(Mode m) {
    switch (m) {
        case Mode::SHA3_224: case Mode::SHA3_256:
        case Mode::SHA3_384: case Mode::SHA3_512: return true;
        default: return false;
    }
}
bool modeIsShake(Mode m) {
    return m == Mode::SHAKE128 || m == Mode::SHAKE256;
}
bool modeIsDuet(Mode m) {
    // In this DUT, SHA-224 and SHA-256 use the duet-capable SHA2-32 path.
    return m == Mode::SHA2_224 || m == Mode::SHA2_256;
}

std::vector<uint8_t> emptyDigestFor(Mode m) {
    std::string hex;
    switch (m) {
        case Mode::SHA2_224:     hex = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"; break;
        case Mode::SHA2_256:     hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; break;
        case Mode::SHA2_384:     hex = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"; break;
        case Mode::SHA2_512:     hex = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"; break;
        case Mode::SHA2_512_224: hex = "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"; break;
        case Mode::SHA2_512_256: hex = "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"; break;
        case Mode::SHA3_224:     hex = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"; break;
        case Mode::SHA3_256:     hex = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"; break;
        case Mode::SHA3_384:     hex = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"; break;
        case Mode::SHA3_512:     hex = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"; break;
        case Mode::SHAKE128:     hex = "7f9c2ba4e88f827d616045507605853e"; break;   // first 128 bits
        case Mode::SHAKE256:     hex = "46b9dd2b0ba88d13233b3feb743eeb24"; break;   // first 128 bits
    }
    try { return hexToBytes(hex); }
    catch (...) { return {}; }
}

std::vector<Mode> applyModeFilter(const TestOptions& opts,
                                  const std::string& testlabel) {
    if (opts.mode_filter.empty()) return kAllModes;
    Mode m;
    if (!modeFromName(opts.mode_filter, m)) {
        std::cerr << "[" << testlabel << "] unknown mode '"
                  << opts.mode_filter << "'. Valid names: ";
        for (auto md : kAllModes) std::cerr << modeName(md) << " ";
        std::cerr << "\n";
        return {};
    }
    return {m};
}

void driveEmptyMessageBlocking(SharmonyDriver& drv, Mode m) {
    if (modeIsDuet(m)) drv.sendMessageDuetMirror({});
    else               drv.sendMessageNative({});
}

bool driveEmptyMessageTry(SharmonyDriver& drv, Mode m,
                          unsigned timeout_cycles) {
    if (modeIsDuet(m)) {
        return drv.trySendBeatDuet(0, 0, 1, 0, 0, 1, timeout_cycles);
    }
    return drv.trySendBeat(0, 0, 0b11, timeout_cycles);
}

void shakeSqueezeStop(SharmonyDriver& drv, int max_cycles) {
    drv.setOutReady(false);
    for (int i = 0; i < max_cycles; ++i) {
        if (drv.acceptStart()) break;   // !busy -> core back in IDLE
        drv.tick();
    }
    drv.setOutReady(true);
}

bool digestMatches(const std::vector<uint64_t>& beats,
                   const std::vector<uint8_t>& exp_md,
                   bool is_duet) {
    const int n_md_bytes = static_cast<int>(exp_md.size());
    if (is_duet) {
        for (size_t b = 0; b < beats.size(); b++) {
            const uint32_t hi_word = uint32_t(beats[b] >> 32);
            const uint32_t lo_word = uint32_t(beats[b] & 0xFFFFFFFFULL);
            for (int j = 0; j < 4; j++) {
                int byte_idx = static_cast<int>(b) * 4 + j;
                if (byte_idx >= n_md_bytes) break;
                uint8_t got_hi = uint8_t((hi_word >> (24 - j*8)) & 0xFF);
                uint8_t got_lo = uint8_t((lo_word >> (24 - j*8)) & 0xFF);
                if (got_hi != exp_md[byte_idx]) return false;
                if (got_lo != exp_md[byte_idx]) return false;
            }
        }
    } else {
        for (size_t b = 0; b < beats.size(); b++) {
            for (int j = 0; j < 8; j++) {
                int byte_idx = static_cast<int>(b) * 8 + j;
                if (byte_idx >= n_md_bytes) break;
                uint8_t got = uint8_t((beats[b] >> (56 - j*8)) & 0xFF);
                if (got != exp_md[byte_idx]) return false;
            }
        }
    }
    return true;
}

void printDigestFailure(const std::string& scenario, Mode m,
                        const std::vector<uint8_t>& exp_md,
                        const std::vector<uint64_t>& got_beats) {
    std::cerr << "[FAIL] " << scenario << " [" << modeName(m) << "] recovery: digest mismatch\n"
              << "       exp = " << SharmonyDriver::bytesToHex(exp_md) << "\n"
              << "       got beats:\n";
    for (size_t i = 0; i < got_beats.size(); i++) {
        std::cerr << "          beat[" << i << "] = ";
        char buf[20];
        std::snprintf(buf, sizeof(buf), "%016lx", (unsigned long)got_beats[i]);
        std::cerr << buf << "\n";
    }
}

bool runRecoveryCheckBlocking(SharmonyDriver& drv, Mode m,
                              const std::string& scenario) {
    auto exp_md = emptyDigestFor(m);
    drv.setMode(m);
    drv.pulseStart();
    driveEmptyMessageBlocking(drv, m);
    drv.endMsg();

    std::vector<uint64_t> beats;
    try {
        beats = drv.collectBeats(digestBeatsFor(m), 4000);
    } catch (const TimeoutError& e) {
        std::cerr << "[FAIL] " << scenario << " [" << modeName(m)
                  << "] recovery: digest collection timed out\n";
        return false;
    }

    // Reverse-overlap: SHA-2 streams the digest in reverse word order (H7..H0).
    if (modeIsSha2(m)) std::reverse(beats.begin(), beats.end());
    if (digestMatches(beats, exp_md, modeIsDuet(m))) return true;
    printDigestFailure(scenario, m, exp_md, beats);
    return false;
}

bool runRecoveryCheckTry(SharmonyDriver& drv, Mode m,
                         const std::string& scenario) {
    auto exp_md = emptyDigestFor(m);
    drv.setMode(m);
    if (!drv.tryPulseStart(200)) {
        std::cerr << "[FAIL] " << scenario << " [" << modeName(m)
                  << "] recovery: pulse_start timed out\n";
        return false;
    }
    if (!driveEmptyMessageTry(drv, m, 500)) {
        std::cerr << "[FAIL] " << scenario << " [" << modeName(m)
                  << "] recovery: empty-message send timed out\n";
        return false;
    }
    drv.tick();
    drv.endMsg();

    auto [ok, beats] = drv.tryCollectBeats(digestBeatsFor(m), 4000);
    if (!ok) {
        std::cerr << "[FAIL] " << scenario << " [" << modeName(m)
                  << "] recovery: digest collection timed out\n";
        return false;
    }

    // Reverse-overlap: SHA-2 streams the digest in reverse word order (H7..H0).
    if (modeIsSha2(m)) std::reverse(beats.begin(), beats.end());
    if (digestMatches(beats, exp_md, modeIsDuet(m))) return true;
    printDigestFailure(scenario, m, exp_md, beats);
    return false;
}

void finalizeErrorScenario(SharmonyDriver& drv, Mode m,
                           const std::string& scenario,
                           Scoreboard& sb,
                           bool violation_ok,
                           bool reset_first) {
    drv.forceIdleInputs();
    if (reset_first) {
        drv.reset();
        drv.forceIdleInputs();
    }
    drv.tick();
    // With reset_first this checks that reset cleared output_valid; without
    // it, that the refused access produced no spurious output at all.
    const bool clear_ok = (!drv.outputValid());
    if (!clear_ok) {
        std::cerr << "[FAIL] " << scenario << " [" << modeName(m)
                  << "]: unexpected output_valid "
                  << (reset_first ? "after reset" : "after refused access")
                  << "\n";
    }
    drv.setOutReady(true);
    const bool recover_ok = runRecoveryCheckTry(drv, m, scenario);

    // Same SHAKE-survives-collectBeats reasoning as the reset finalizer.
    drv.forceIdleInputs();
    drv.reset();
    drv.forceIdleInputs();
    drv.tick();
    drv.setMode(m);
    drv.setOutReady(true);

    if (clear_ok && recover_ok && violation_ok) {
        std::cout << "[PASS] " << scenario << " [" << modeName(m) << "]\n";
        sb.pass();
    } else {
        sb.fail();
    }
}

}  // namespace sharmony
