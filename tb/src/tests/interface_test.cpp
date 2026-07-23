///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Streaming/control-interface stress test for the Verilator C++ testbench.
//
// This test sweeps the 12 hash/XOF modes (cSHAKE has dedicated tests) and
// stresses the existing ready/valid
// and control interface.  The intent is protocol coverage, not additional KAT
// volume: each scenario uses a small known-answer vector, stresses the
// interface timing, and then checks the digest against the corresponding RSP
// answer.
//
// Run:
//   make run-interface
//   make run-interface MODE=HASH_SHA3_256
//
///////////////////////////////////////////////////////////////////////////////////////

#include "../SharmonyDriver.hpp"
#include "../TestRegistry.hpp"
#include "../RspParser.hpp"
#include "common/RefHash.hpp"
#include "common/ScenarioCommon.hpp"

#include "Vsharmony_verilator_wrapper.h"   // raw top-level ports (start/zeroize)

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace sharmony {

namespace {

struct ModeCase {
    Mode mode;
    const char* label;
    const char* rsp_path;
};

const std::vector<ModeCase>& allModeCases() {
    static const std::vector<ModeCase> kCases = {
        {Mode::SHA2_224,     "sha224",      "tb/src/tests/data/SHA224ShortMsg.rsp"},
        {Mode::SHA2_256,     "sha256",      "tb/src/tests/data/SHA256ShortMsg.rsp"},
        {Mode::SHA2_384,     "sha384",      "tb/src/tests/data/SHA384ShortMsg.rsp"},
        {Mode::SHA2_512,     "sha512",      "tb/src/tests/data/SHA512ShortMsg.rsp"},
        {Mode::SHA2_512_224, "sha512_224",  "tb/src/tests/data/SHA512_224ShortMsg.rsp"},
        {Mode::SHA2_512_256, "sha512_256",  "tb/src/tests/data/SHA512_256ShortMsg.rsp"},
        {Mode::SHA3_224,     "sha3_224",    "tb/src/tests/data/SHA3_224ShortMsg.rsp"},
        {Mode::SHA3_256,     "sha3_256",    "tb/src/tests/data/SHA3_256ShortMsg.rsp"},
        {Mode::SHA3_384,     "sha3_384",    "tb/src/tests/data/SHA3_384ShortMsg.rsp"},
        {Mode::SHA3_512,     "sha3_512",    "tb/src/tests/data/SHA3_512ShortMsg.rsp"},
        {Mode::SHAKE128,     "shake128",    "tb/src/tests/data/SHAKE128ShortMsg.rsp"},
        {Mode::SHAKE256,     "shake256",    "tb/src/tests/data/SHAKE256ShortMsg.rsp"},
    };
    return kCases;
}

struct IfaceScoreboard {
    int pass = 0;
    int fail = 0;
    int skipped = 0;

    void record(const std::string& name, bool ok) {
        if (ok) {
            pass++;
            std::cout << "[PASS] [interface] " << name << "\n";
        } else {
            fail++;
            std::cerr << "[FAIL] [interface] " << name << "\n";
        }
    }

    void skip(const std::string& name, const std::string& reason) {
        skipped++;
        std::cout << "[SKIP] [interface] " << name << " -- " << reason << "\n";
    }
};

static void waitCycles(SharmonyDriver& drv, int n) {
    for (int i = 0; i < n; ++i) drv.tick();
}

static uint64_t packBeatMSBFirstLocal(const uint8_t* p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n && i < 8; ++i) {
        v |= static_cast<uint64_t>(p[i]) << (56 - 8 * static_cast<int>(i));
    }
    return v;
}

static uint32_t packLaneMSBFirstLocal(const uint8_t* p, size_t n) {
    uint32_t v = 0;
    for (size_t i = 0; i < n && i < 4; ++i) {
        v |= static_cast<uint32_t>(p[i]) << (24 - 8 * static_cast<int>(i));
    }
    return v;
}

static const ModeCase* findModeCase(Mode mode) {
    for (const auto& c : allModeCases()) {
        if (c.mode == mode) return &c;
    }
    return nullptr;
}

static std::vector<ModeCase> selectedModeCases(const TestOptions& opts) {
    if (opts.mode_filter.empty()) return allModeCases();

    Mode selected;
    if (!modeFromName(opts.mode_filter, selected)) {
        std::cerr << "[interface] unknown mode '" << opts.mode_filter
                  << "'. Valid names: ";
        for (const auto& c : allModeCases()) std::cerr << modeName(c.mode) << " ";
        std::cerr << "\n";
        return {};
    }

    const ModeCase* c = findModeCase(selected);
    if (!c) return {};
    return {*c};
}

static std::vector<uint8_t> expectedPrefixForMode(Mode mode, const RspVector& vec) {
    const int n = digestBytesFor(mode);
    if (static_cast<int>(vec.md.size()) < n) return {};
    return std::vector<uint8_t>(vec.md.begin(), vec.md.begin() + n);
}

static std::vector<uint8_t> firstBytes(const std::vector<uint8_t>& v, size_t n) {
    const size_t take = std::min(n, v.size());
    return std::vector<uint8_t>(v.begin(), v.begin() + take);
}

static RspVector findVector(const ModeCase& mc,
                            const std::vector<int>& preferred_len_bits,
                            bool require_multi_beat) {
    auto vectors = parseRsp(mc.rsp_path);
    const int compare_len = digestBytesFor(mc.mode);
    const size_t min_msg_bytes = modeIsDuet(mc.mode) ? 5u : 9u;

    auto usable = [&](const RspVector& v) -> bool {
        if (static_cast<int>(v.md.size()) < compare_len) return false;
        if (require_multi_beat && v.msg.size() < min_msg_bytes) return false;
        return true;
    };

    for (int len : preferred_len_bits) {
        for (const auto& v : vectors) {
            if (v.len_bits == len && usable(v)) return v;
        }
    }
    for (const auto& v : vectors) {
        if (usable(v)) return v;
    }

    throw std::runtime_error(std::string(mc.rsp_path)
                             + " does not contain a usable vector for "
                             + mc.label);
}

static bool sendMessageWithGaps(SharmonyDriver& drv,
                                Mode mode,
                                const std::vector<uint8_t>& msg,
                                const std::vector<unsigned>& gaps,
                                unsigned timeout_cycles = 1000) {
    if (modeIsDuet(mode)) {
        if (msg.empty()) {
            const bool ok = drv.trySendBeatDuet(0, 0, 1, 0, 0, 1, timeout_cycles);
            drv.endMsg();
            return ok;
        }

        size_t off = 0;
        size_t beat_idx = 0;
        while (off < msg.size()) {
            const size_t remain = msg.size() - off;
            const size_t take = std::min<size_t>(remain, 4);
            const bool last = (off + take == msg.size());
            const uint32_t lane = packLaneMSBFirstLocal(msg.data() + off, take);

            const bool ok = drv.trySendBeatDuet(lane, static_cast<uint8_t>(take), last ? 1 : 0,
                                                lane, static_cast<uint8_t>(take), last ? 1 : 0,
                                                timeout_cycles);
            drv.endMsg();
            if (!ok) return false;

            if (!last && !gaps.empty()) {
                waitCycles(drv, static_cast<int>(gaps[beat_idx % gaps.size()]));
            }

            off += take;
            beat_idx++;
        }
        drv.endMsg();
        return true;
    }

    if (msg.empty()) {
        const bool ok = drv.trySendBeat(0, 0, 0b11, timeout_cycles);
        drv.endMsg();
        return ok;
    }

    size_t off = 0;
    size_t beat_idx = 0;
    while (off < msg.size()) {
        const size_t remain = msg.size() - off;
        const size_t take = std::min<size_t>(remain, 8);
        const bool last = (off + take == msg.size());
        const uint64_t beat = packBeatMSBFirstLocal(msg.data() + off, take);

        const bool ok = drv.trySendBeat(beat, static_cast<uint8_t>(take),
                                        static_cast<uint8_t>(last ? 0b11 : 0b00),
                                        timeout_cycles);
        drv.endMsg();
        if (!ok) return false;

        if (!last && !gaps.empty()) {
            waitCycles(drv, static_cast<int>(gaps[beat_idx % gaps.size()]));
        }

        off += take;
        beat_idx++;
    }
    drv.endMsg();
    return true;
}

// Collect output beats by sampling output_data before the tick that accepts
// the beat.  This is important for output-backpressure checks: the currently
// valid beat is captured first, then output_ready=1 lets the DUT advance.
static bool collectBeatsReadyValid(SharmonyDriver& drv,
                                   size_t n_beats,
                                   std::vector<uint64_t>& out,
                                   unsigned timeout_per_beat = 10000) {
    out.clear();
    out.reserve(n_beats);

    for (size_t b = 0; b < n_beats; ++b) {
        bool seen = false;
        for (unsigned t = 0; t < timeout_per_beat; ++t) {
            if (drv.outputValid()) {
                out.push_back(drv.outputData());
                drv.tick();
                seen = true;
                break;
            }
            drv.tick();
        }
        if (!seen) return false;
    }
    return true;
}

static bool digestMatchesMode(Mode mode,
                              const std::vector<uint64_t>& beats_in,
                              const std::vector<uint8_t>& expected,
                              const std::string& context) {
    // SHA-2 streams the digest in reverse word order (H7..H0); un-reverse first.
    std::vector<uint64_t> beats = beats_in;
    if (modeIsSha2(mode)) std::reverse(beats.begin(), beats.end());
    const bool ok = digestMatches(beats, expected, modeIsDuet(mode));
    if (!ok) {
        std::cerr << "[interface] " << context << " [" << modeName(mode)
                  << "]: digest mismatch\n"
                  << "  exp = " << SharmonyDriver::bytesToHex(expected) << "\n";
        if (modeIsDuet(mode)) {
            auto got_hi = SharmonyDriver::beatsToHiLaneBytes(beats, expected.size());
            auto got_lo = SharmonyDriver::beatsToLoLaneBytes(beats, expected.size());
            std::cerr << "  hi  = " << SharmonyDriver::bytesToHex(got_hi) << "\n"
                      << "  lo  = " << SharmonyDriver::bytesToHex(got_lo) << "\n";
        } else {
            auto got = SharmonyDriver::beatsToBytes(beats, expected.size());
            std::cerr << "  got = " << SharmonyDriver::bytesToHex(got) << "\n";
        }
    }
    return ok;
}

static bool runTransaction(SharmonyDriver& drv,
                           const ModeCase& mc,
                           const RspVector& vec,
                           const std::vector<unsigned>& input_gaps,
                           std::vector<uint64_t>& beats,
                           bool reset_first = true) {
    if (reset_first) drv.reset();
    drv.setOutReady(true);
    drv.setMode(mc.mode);
    drv.pulseStart();
    if (!sendMessageWithGaps(drv, mc.mode, vec.msg, input_gaps)) return false;
    return collectBeatsReadyValid(drv, digestBeatsFor(mc.mode), beats);
}

static Mode hostileModeFor(Mode mode) {
    return mode == Mode::SHA3_256 ? Mode::SHA2_512 : Mode::SHA3_256;
}

static std::string scenarioName(const char* scenario, const ModeCase& mc) {
    return std::string(scenario) + "_" + mc.label;
}

//-------------------------------------------------------------------------------------
// Integrated reset/recovery scenarios.
//
// Each reset scenario intentionally aborts the DUT in a different state,
// asserts reset, then proves clean recovery by running the empty-message
// digest for the same mode.
//-------------------------------------------------------------------------------------
static void resetPrepare(SharmonyDriver& drv, Mode m) {
    drv.reset();
    drv.tick();
    drv.setMode(m);
    drv.setOutReady(true);
    waitCycles(drv, 2);
}

static void resetSendShortFinal(SharmonyDriver& drv, Mode m) {
    if (modeIsDuet(m)) {
        drv.sendBeatDuet(0x61626364, 4, 1,
                         0x61626364, 4, 1);
    } else {
        drv.sendBeat(0x6162636465666768ULL, 8, 0b11);
    }
    drv.endMsg();
}

static bool resetFinalizeAndRecover(SharmonyDriver& drv,
                                    Mode m,
                                    const std::string& scenario) {
    drv.reset();
    drv.tick();

    const bool clear_ok = !drv.outputValid();
    if (!clear_ok) {
        std::cerr << "[interface] " << scenario << " [" << modeName(m)
                  << "]: output_valid not cleared after reset\n";
    }

    drv.setOutReady(true);
    const bool recover_ok = runRecoveryCheckBlocking(drv, m, scenario);

    // Leave the DUT idle for the next interface scenario.  This is especially
    // important for SHAKE/XOF, which can otherwise remain in squeeze/output.
    drv.reset();
    drv.tick();
    drv.setMode(m);
    drv.setOutReady(true);

    return clear_ok && recover_ok;
}

static bool scenarioResetWhileIdle(SharmonyDriver& drv, Mode m) {
    resetPrepare(drv, m);
    return resetFinalizeAndRecover(drv, m, "reset_while_idle");
}

static bool scenarioResetAfterStart(SharmonyDriver& drv, Mode m) {
    resetPrepare(drv, m);
    drv.pulseStart();
    waitCycles(drv, 3);
    return resetFinalizeAndRecover(drv, m, "reset_after_start");
}

static bool scenarioResetMidStream(SharmonyDriver& drv, Mode m) {
    resetPrepare(drv, m);
    drv.pulseStart();
    if (modeIsDuet(m)) {
        for (int i = 0; i < 5; ++i) {
            drv.sendBeatDuet(0xAAAAAAAA, 4, 0,
                             0xAAAAAAAA, 4, 0);
        }
    } else {
        for (int i = 0; i < 5; ++i) {
            drv.sendBeat(0xAAAAAAAAAAAAAAAAULL, 8, 0);
        }
    }
    drv.endMsg();
    waitCycles(drv, 2);
    return resetFinalizeAndRecover(drv, m, "reset_mid_stream");
}

static bool scenarioResetAfterFinalPreOutput(SharmonyDriver& drv, Mode m) {
    resetPrepare(drv, m);
    drv.pulseStart();
    resetSendShortFinal(drv, m);
    waitCycles(drv, 8);
    return resetFinalizeAndRecover(drv, m, "reset_after_final_pre_output");
}

static bool scenarioResetDuringOutput(SharmonyDriver& drv, Mode m) {
    resetPrepare(drv, m);
    drv.pulseStart();
    resetSendShortFinal(drv, m);
    if (!drv.waitOutputValid(4000)) {
        std::cerr << "[interface] reset_during_output [" << modeName(m)
                  << "]: warning: output_valid not seen before reset\n";
    }
    drv.tick();
    return resetFinalizeAndRecover(drv, m, "reset_during_output");
}

static bool scenarioResetUnderBackpressure(SharmonyDriver& drv, Mode m) {
    resetPrepare(drv, m);
    drv.pulseStart();
    resetSendShortFinal(drv, m);
    drv.setOutReady(false);
    if (!drv.waitOutputValid(4000)) {
        std::cerr << "[interface] reset_under_backpressure [" << modeName(m)
                  << "]: warning: output_valid not seen before reset\n";
    }
    waitCycles(drv, 5);
    return resetFinalizeAndRecover(drv, m, "reset_under_backpressure");
}

static bool scenarioResetSha2Phase(SharmonyDriver& drv, Mode m, int phase) {
    resetPrepare(drv, m);
    drv.pulseStart();
    resetSendShortFinal(drv, m);
    waitCycles(drv, phase);
    return resetFinalizeAndRecover(drv, m,
        "reset_sha2_phase_at_" + std::to_string(phase));
}

static bool scenarioResetKeccakPhase(SharmonyDriver& drv, Mode m, int phase) {
    resetPrepare(drv, m);
    drv.pulseStart();
    drv.sendBeat(0x6162636465666768ULL, 8, 0b11);
    drv.endMsg();
    waitCycles(drv, phase);
    return resetFinalizeAndRecover(drv, m,
        "reset_keccak_phase_at_" + std::to_string(phase));
}

static bool scenarioResetShakePartialXof(SharmonyDriver& drv, Mode m) {
    resetPrepare(drv, m);
    drv.pulseStart();
    drv.sendBeat(0x6162636465666768ULL, 8, 0b11);
    drv.endMsg();
    if (!drv.waitOutputValid(4000)) {
        std::cerr << "[interface] reset_shake_partial_xof [" << modeName(m)
                  << "]: warning: output_valid not seen before reset\n";
    }
    drv.tick();
    return resetFinalizeAndRecover(drv, m, "reset_shake_partial_xof");
}

static bool scenarioResetDuetBalancedStream(SharmonyDriver& drv, Mode m) {
    resetPrepare(drv, m);
    drv.pulseStart();
    for (int k = 0; k < 4; ++k) {
        drv.sendBeatDuet(0xAAAAAAAA, 4, 0,
                         0xBBBBBBBB, 4, 0);
    }
    drv.endMsg();
    waitCycles(drv, 2);
    return resetFinalizeAndRecover(drv, m, "reset_duet_balanced_stream");
}

static bool scenarioResetDuetHighFinalLowStreaming(SharmonyDriver& drv, Mode m) {
    resetPrepare(drv, m);
    drv.pulseStart();
    drv.sendBeatDuet(0x61626300, 3, 1,
                     0xAAAAAAAA, 4, 0);
    for (int k = 0; k < 3; ++k) {
        drv.sendBeatDuet(0, 0, 0,
                         0xAAAAAAAA, 4, 0);
    }
    drv.endMsg();
    waitCycles(drv, 2);
    return resetFinalizeAndRecover(drv, m,
        "reset_duet_high_finalized_low_streaming");
}

static bool scenarioResetDuetLowFinalHighStreaming(SharmonyDriver& drv, Mode m) {
    resetPrepare(drv, m);
    drv.pulseStart();
    drv.sendBeatDuet(0xBBBBBBBB, 4, 0,
                     0x61626300, 3, 1);
    for (int k = 0; k < 3; ++k) {
        drv.sendBeatDuet(0xBBBBBBBB, 4, 0,
                         0, 0, 0);
    }
    drv.endMsg();
    waitCycles(drv, 2);
    return resetFinalizeAndRecover(drv, m,
        "reset_duet_low_finalized_high_streaming");
}

static bool scenarioResetDuetDeferredPad80(SharmonyDriver& drv, Mode m) {
    resetPrepare(drv, m);
    drv.pulseStart();
    drv.sendBeatDuet(0x61626364, 4, 1,
                     0xAAAAAAAA, 4, 0);
    drv.endMsg();
    waitCycles(drv, 1);
    return resetFinalizeAndRecover(drv, m, "reset_duet_deferred_pad80");
}

static void runMergedResetScenarios(SharmonyDriver& drv,
                                    const ModeCase& mc,
                                    IfaceScoreboard& sb) {
    sb.record(scenarioName("reset_while_idle", mc),
              scenarioResetWhileIdle(drv, mc.mode));
    sb.record(scenarioName("reset_after_start", mc),
              scenarioResetAfterStart(drv, mc.mode));
    sb.record(scenarioName("reset_mid_stream", mc),
              scenarioResetMidStream(drv, mc.mode));
    sb.record(scenarioName("reset_after_final_pre_output", mc),
              scenarioResetAfterFinalPreOutput(drv, mc.mode));
    sb.record(scenarioName("reset_during_output", mc),
              scenarioResetDuringOutput(drv, mc.mode));
    sb.record(scenarioName("reset_under_backpressure", mc),
              scenarioResetUnderBackpressure(drv, mc.mode));

    if (modeIsSha2(mc.mode)) {
        const int phases[4] = {15, 25, 40, 60};
        for (int phase : phases) {
            sb.record(scenarioName(("reset_sha2_phase_at_" + std::to_string(phase)).c_str(), mc),
                      scenarioResetSha2Phase(drv, mc.mode, phase));
        }
    }

    if (modeIsSha3(mc.mode) || modeIsShake(mc.mode)) {
        const int phases[3] = {10, 28, 50};
        for (int phase : phases) {
            sb.record(scenarioName(("reset_keccak_phase_at_" + std::to_string(phase)).c_str(), mc),
                      scenarioResetKeccakPhase(drv, mc.mode, phase));
        }
    }

    if (modeIsShake(mc.mode)) {
        sb.record(scenarioName("reset_shake_partial_xof", mc),
                  scenarioResetShakePartialXof(drv, mc.mode));
    }

    if (modeIsDuet(mc.mode)) {
        sb.record(scenarioName("reset_duet_balanced_stream", mc),
                  scenarioResetDuetBalancedStream(drv, mc.mode));
        sb.record(scenarioName("reset_duet_high_finalized_low_streaming", mc),
                  scenarioResetDuetHighFinalLowStreaming(drv, mc.mode));
        sb.record(scenarioName("reset_duet_low_finalized_high_streaming", mc),
                  scenarioResetDuetLowFinalHighStreaming(drv, mc.mode));
        sb.record(scenarioName("reset_duet_deferred_pad80", mc),
                  scenarioResetDuetDeferredPad80(drv, mc.mode));
    }
}

//-------------------------------------------------------------------------------------
//  Start acceptance: a second start request while active must not be accepted, and
//  must not corrupt the original transaction.
//-------------------------------------------------------------------------------------
static bool scenarioStartWhileBusy(SharmonyDriver& drv, const ModeCase& mc) {
    const auto vec = findVector(mc, {24, 64, 0}, false);
    const auto exp = expectedPrefixForMode(mc.mode, vec);

    drv.reset();
    drv.setMode(mc.mode);
    drv.setOutReady(true);
    drv.pulseStart();

    const bool accepted_restart = drv.tryPulseStart(20);
    if (accepted_restart) {
        std::cerr << "[interface] start_while_busy [" << modeName(mc.mode)
                  << "]: busy=0 (restart allowed) while still busy\n";
        return false;
    }

    if (!sendMessageWithGaps(drv, mc.mode, vec.msg, {})) return false;
    std::vector<uint64_t> beats;
    if (!collectBeatsReadyValid(drv, digestBeatsFor(mc.mode), beats)) return false;
    return digestMatchesMode(mc.mode, beats, exp, "start_while_busy");
}

//-------------------------------------------------------------------------------------
//  Start/busy timing: after a legal start pulse, busy must assert immediately when
//  start is deasserted. This catches a one-cycle bubble where start has gone
//  low but busy has not yet gone high.
//-------------------------------------------------------------------------------------
static bool scenarioStartLowBusyHighImmediate(SharmonyDriver& drv, const ModeCase& mc) {
    drv.reset();
    drv.setMode(mc.mode);
    drv.setOutReady(true);
    waitCycles(drv, 2);

    if (drv.busy()) {
        std::cerr << "[interface] start_low_busy_high_immediate [" << modeName(mc.mode)
                  << "]: engine unexpectedly busy before start\n";
        return false;
    }

    // Manually issue the start pulse so we can check the exact cycle after
    // start is driven low, without hiding timing inside pulseStart().
    drv.model()->start = 1;
    drv.tick();

    drv.model()->start = 0;

    // Immediate check: no extra tick is allowed here.
    if (!drv.busy()) {
        std::cerr << "[interface] start_low_busy_high_immediate [" << modeName(mc.mode)
                  << "]: start went low but busy was not high immediately\n";
        drv.reset();
        return false;
    }

    // Clean up this intentionally incomplete transaction.
    drv.reset();
    drv.tick();
    drv.setOutReady(true);
    return true;
}

//-------------------------------------------------------------------------------------
// Zeroize/busy timing (twin of the start/busy check).  After a legal one-cycle
// zeroize pulse, busy must assert immediately when zeroize is deasserted.
// This catches the one-cycle bubble where a host could read busy=0 right
// after the pulse and conclude zeroization already completed -- before the
// wipe has even begun.
//-------------------------------------------------------------------------------------
static bool scenarioZeroizeLowBusyHighImmediate(SharmonyDriver& drv, const ModeCase& mc) {
    drv.reset();
    drv.setMode(mc.mode);
    drv.setOutReady(true);
    waitCycles(drv, 2);

    if (drv.busy()) {
        std::cerr << "[interface] zeroize_low_busy_high_immediate [" << modeName(mc.mode)
                  << "]: engine unexpectedly busy before zeroize\n";
        return false;
    }

    // One-cycle zeroize pulse, post-edge placement; check the exact cycle
    // after zeroize is driven low -- no extra tick is allowed here.
    drv.setZeroize(true);
    drv.tick();
    drv.setZeroize(false);

    if (!drv.busy()) {
        std::cerr << "[interface] zeroize_low_busy_high_immediate [" << modeName(mc.mode)
                  << "]: zeroize went low but busy was not high immediately\n";
        drv.reset();
        return false;
    }

    // The zeroize window must then complete and return cleanly to idle.
    int guard = 0;
    while (drv.busy() && guard++ < 64) drv.tick();
    if (drv.busy()) {
        std::cerr << "[interface] zeroize_low_busy_high_immediate [" << modeName(mc.mode)
                  << "]: still busy after the zeroize window -- engine stuck\n";
        return false;
    }
    return true;
}

//-------------------------------------------------------------------------------------
// Start-vs-zeroize arbitration: start and zeroize asserted on the SAME cycle, from idle.
// Contract: zeroize wins.  The coincident start must be ignored (no hash is
// launched and no digest is ever produced), the zeroize must be issued
// (busy asserts for the zeroize window), and the engine must then return
// cleanly to idle and run a fresh, correct transaction.
//-------------------------------------------------------------------------------------
static bool scenarioStartZeroizeSameCycle(SharmonyDriver& drv, const ModeCase& mc) {
    const auto vec = findVector(mc, {24, 64, 0}, false);
    const auto exp = expectedPrefixForMode(mc.mode, vec);

    drv.reset();
    drv.setMode(mc.mode);
    drv.setOutReady(true);
    waitCycles(drv, 2);

    if (drv.busy()) {
        std::cerr << "[interface] start_zeroize_same_cycle [" << modeName(mc.mode)
                  << "]: engine unexpectedly busy before the coincident pulse\n";
        return false;
    }

    // Drive start=1 and zeroize=1 so both are sampled on the SAME posedge.
    drv.model()->start = 1;
    drv.setZeroize(true);
    drv.tick();
    drv.model()->start = 0;
    drv.setZeroize(false);

    // Watch the zeroize window: busy must assert (zeroize honored) and no
    // output_valid may ever appear (the coincident start must be ignored).
    bool saw_busy = false;
    for (int i = 0; i < 64; ++i) {
        if (drv.busy()) saw_busy = true;
        if (drv.outputValid()) {
            std::cerr << "[interface] start_zeroize_same_cycle [" << modeName(mc.mode)
                      << "]: spurious output_valid -- coincident start was not ignored\n";
            return false;
        }
        if (saw_busy && !drv.busy()) break;  // zeroize finished, back to idle
        drv.tick();
    }

    if (!saw_busy) {
        std::cerr << "[interface] start_zeroize_same_cycle [" << modeName(mc.mode)
                  << "]: busy never asserted -- zeroize was not issued\n";
        return false;
    }
    if (drv.busy()) {
        std::cerr << "[interface] start_zeroize_same_cycle [" << modeName(mc.mode)
                  << "]: still busy after the zeroize window -- engine stuck\n";
        return false;
    }

    // Recovery: a fresh transaction (no reset) must produce the correct digest,
    // proving the ignored start left no residual state.
    std::vector<uint64_t> beats;
    if (!runTransaction(drv, mc, vec, {}, beats, /*reset_first=*/false)) return false;
    return digestMatchesMode(mc.mode, beats, exp, "start_zeroize_same_cycle");
}

//-------------------------------------------------------------------------------------
// Zeroize-window handoff: start pulsed on the exact cycle the zeroize window ends.
// A start issued at the first idle cycle after a zeroize (the cycle busy
// deasserts) must be accepted -- not dropped at the busy->idle boundary --
// and produce a correct digest.  This probes the zeroize->idle handoff of
// the capture-enable gate (start && !busy / start && !busy_comb).
//-------------------------------------------------------------------------------------
static bool scenarioStartAtZeroizeWindowEnd(SharmonyDriver& drv, const ModeCase& mc) {
    const auto vec = findVector(mc, {24, 64, 0}, false);
    const auto exp = expectedPrefixForMode(mc.mode, vec);

    drv.reset();
    drv.setMode(mc.mode);
    drv.setOutReady(true);
    waitCycles(drv, 2);

    if (drv.busy()) {
        std::cerr << "[interface] start_at_zeroize_window_end [" << modeName(mc.mode)
                  << "]: engine unexpectedly busy before zeroize\n";
        return false;
    }

    // 1-cycle zeroize from idle.
    drv.setZeroize(true);
    drv.tick();
    drv.setZeroize(false);

    // Run through the zeroize window: wait for busy to engage, then advance
    // to the exact cycle it deasserts (the window end == first idle cycle).
    int guard = 0;
    while (!drv.busy() && guard++ < 16) drv.tick();   // busy engages
    if (!drv.busy()) {
        std::cerr << "[interface] start_at_zeroize_window_end [" << modeName(mc.mode)
                  << "]: busy never asserted -- zeroize not issued\n";
        return false;
    }
    guard = 0;
    while (drv.busy() && guard++ < 64) drv.tick();    // exits on the first idle cycle
    if (drv.busy()) {
        std::cerr << "[interface] start_at_zeroize_window_end [" << modeName(mc.mode)
                  << "]: zeroize window never ended\n";
        return false;
    }

    // On this exact first-idle cycle, pulse start, then a settle cycle (matches
    // pulseStart: lets the registered-start/input-skid path in REG_IO=1 advance
    // before the first beat) and stream.
    drv.model()->start = 1;
    drv.tick();
    drv.model()->start = 0;
    drv.tick();

    if (!sendMessageWithGaps(drv, mc.mode, vec.msg, {})) {
        std::cerr << "[interface] start_at_zeroize_window_end [" << modeName(mc.mode)
                  << "]: message not accepted -- start dropped at the window end\n";
        return false;
    }
    std::vector<uint64_t> beats;
    if (!collectBeatsReadyValid(drv, digestBeatsFor(mc.mode), beats)) {
        std::cerr << "[interface] start_at_zeroize_window_end [" << modeName(mc.mode)
                  << "]: digest collection timed out\n";
        return false;
    }
    return digestMatchesMode(mc.mode, beats, exp, "start_at_zeroize_window_end");
}

//-------------------------------------------------------------------------------------
//  Control stability: changing mode while busy should not corrupt the already-started
//  operation.  This verifies that mode is latched or otherwise protected for an
//  active hash.
//-------------------------------------------------------------------------------------
static bool scenarioModeChangeWhileBusy(SharmonyDriver& drv, const ModeCase& mc) {
    const auto vec = findVector(mc, {24, 64, 0}, false);
    const auto exp = expectedPrefixForMode(mc.mode, vec);

    drv.reset();
    drv.setMode(mc.mode);
    drv.setOutReady(true);
    drv.pulseStart();

    drv.setMode(hostileModeFor(mc.mode));

    if (!sendMessageWithGaps(drv, mc.mode, vec.msg, {})) return false;
    std::vector<uint64_t> beats;
    if (!collectBeatsReadyValid(drv, digestBeatsFor(mc.mode), beats)) return false;

    drv.setMode(mc.mode);
    return digestMatchesMode(mc.mode, beats, exp, "mode_change_while_busy");
}

//-------------------------------------------------------------------------------------
//  Input streaming: input_valid gaps during a multi-beat stream.
//-------------------------------------------------------------------------------------
static bool scenarioInputHandshake(SharmonyDriver& drv, const ModeCase& mc) {
    const auto vec = findVector(mc, {256, 128, 64}, true);
    const auto exp = expectedPrefixForMode(mc.mode, vec);
    std::vector<uint64_t> beats;
    const bool ok = runTransaction(drv, mc, vec, {0, 1, 3, 0, 2}, beats);
    return ok && digestMatchesMode(mc.mode, beats, exp, "input_handshake");
}

//-------------------------------------------------------------------------------------
//  Input streaming stress: longer deterministic input-valid gaps during
//  a multi-beat message.  This is stronger than input_handshake but still
//  reproducible, so failures map to the same waveform every run.
//-------------------------------------------------------------------------------------
static bool scenarioAggressiveInputGaps(SharmonyDriver& drv, const ModeCase& mc) {
    const auto vec = findVector(mc, {512, 256, 128, 64}, true);
    const auto exp = expectedPrefixForMode(mc.mode, vec);
    std::vector<uint64_t> beats;
    const std::vector<unsigned> gaps = {9, 0, 17, 1, 0, 3, 11, 0, 5, 2, 0, 13};
    const bool ok = runTransaction(drv, mc, vec, gaps, beats);
    return ok && digestMatchesMode(mc.mode, beats, exp, "aggressive_input_gaps");
}

//-------------------------------------------------------------------------------------
//  Output streaming: hold output_ready low while output_valid is asserted.  The first
//  output beat must remain valid and stable until output_ready is released.
//-------------------------------------------------------------------------------------
static bool scenarioOutputBackpressure(SharmonyDriver& drv, const ModeCase& mc) {
    const auto vec = findVector(mc, {24, 0, 8, 64}, false);
    const auto exp = expectedPrefixForMode(mc.mode, vec);

    drv.reset();
    drv.setMode(mc.mode);
    drv.setOutReady(true);
    drv.pulseStart();
    if (!sendMessageWithGaps(drv, mc.mode, vec.msg, {})) return false;

    drv.setOutReady(false);
    if (!drv.waitOutputValid(6000)) {
        std::cerr << "[interface] output_backpressure [" << modeName(mc.mode)
                  << "]: output_valid timeout\n";
        return false;
    }

    const uint64_t stable = drv.outputData();
    for (int i = 0; i < 6; ++i) {
        if (!drv.outputValid()) {
            std::cerr << "[interface] output_backpressure [" << modeName(mc.mode)
                      << "]: output_valid dropped under backpressure\n";
            drv.setOutReady(true);
            return false;
        }
        if (drv.outputData() != stable) {
            std::cerr << "[interface] output_backpressure [" << modeName(mc.mode)
                      << "]: output_data changed under backpressure\n";
            drv.setOutReady(true);
            return false;
        }
        drv.tick();
    }

    drv.setOutReady(true);
    std::vector<uint64_t> beats;
    if (!collectBeatsReadyValid(drv, digestBeatsFor(mc.mode), beats)) return false;
    return digestMatchesMode(mc.mode, beats, exp, "output_backpressure");
}

//-------------------------------------------------------------------------------------
//  Output streaming stress: apply output backpressure before every digest
//  beat.  SHAKE/XOF is intentionally excluded by the caller because its output
//  stream has different termination semantics.
//-------------------------------------------------------------------------------------
static bool scenarioOutputBackpressureEveryBeat(SharmonyDriver& drv, const ModeCase& mc) {
    const auto vec = findVector(mc, {24, 0, 8, 64}, false);
    const auto exp = expectedPrefixForMode(mc.mode, vec);

    drv.reset();
    drv.setMode(mc.mode);
    drv.setOutReady(true);
    drv.pulseStart();
    if (!sendMessageWithGaps(drv, mc.mode, vec.msg, {})) return false;

    std::vector<uint64_t> beats;
    beats.reserve(digestBeatsFor(mc.mode));

    for (size_t i = 0; i < digestBeatsFor(mc.mode); ++i) {
        drv.setOutReady(false);
        if (!drv.waitOutputValid(6000)) {
            std::cerr << "[interface] output_backpressure_every_beat [" << modeName(mc.mode)
                      << "]: output_valid timeout at beat " << i << "\n";
            drv.setOutReady(true);
            return false;
        }

        const uint64_t stable = drv.outputData();
        static const int kOutputHoldPattern[] = {0,1,0,2,0};
        const int hold_cycles = kOutputHoldPattern[i % 5];
        for (int h = 0; h < hold_cycles; ++h) {
            if (!drv.outputValid()) {
                std::cerr << "[interface] output_backpressure_every_beat [" << modeName(mc.mode)
                          << "]: output_valid dropped at beat " << i << "\n";
                drv.setOutReady(true);
                return false;
            }
            if (drv.outputData() != stable) {
                std::cerr << "[interface] output_backpressure_every_beat [" << modeName(mc.mode)
                          << "]: output_data changed at beat " << i << "\n";
                drv.setOutReady(true);
                return false;
            }
            drv.tick();
        }

        beats.push_back(stable);
        drv.setOutReady(true);
        drv.tick();
    }

    drv.setOutReady(true);
    return digestMatchesMode(mc.mode, beats, exp, "output_backpressure_every_beat");
}

//-------------------------------------------------------------------------------------
// XOF squeeze-stop residue contract. Output backpressure is intentionally
// unsupported for SHAKE/XOF; these scenarios pin down what a squeeze stop
// actually leaves behind instead. When a squeeze is terminated by
// deasserting output_ready, the registered output boundary
// (REG_IO=1) HOLDS the offered beat plus up to two staged look-ahead words
// after the core returns to IDLE (output_valid stays high, data frozen); the
// combinational boundary (REG_IO=0) holds nothing. The residue is cleared
// only by resetn, zeroize, or the next start. Both configurations are handled
// behaviorally: the checks key off whether a residue is advertised.
// Reference = the DUT's own uninterrupted squeeze of the same message
// (differential, KAT-independent).

static std::vector<uint8_t> xofPatternMsg(size_t len, uint8_t seed) {
    std::vector<uint8_t> m(len);
    for (size_t i = 0; i < len; ++i) m[i] = (uint8_t)(seed ^ (i * 31));
    return m;
}

// Start one XOF squeeze and leave it streaming (ready high).
static void xofStartSqueeze(SharmonyDriver& drv, Mode m,
                            const std::vector<uint8_t>& msg) {
    drv.reset();
    drv.setMode(m);
    drv.setOutReady(true);
    drv.setStateLoad(false); drv.setStateSave(false); drv.setStateCache(false);
    drv.pulseStart();
    drv.sendMessageNative(msg);
    drv.endMsg();
}

// Drain every currently-offered beat: collect while output_valid holds,
// stop after `idle_limit` consecutive valid-low cycles.
static std::vector<uint64_t> xofDrainWhileValid(SharmonyDriver& drv,
                                                unsigned idle_limit) {
    std::vector<uint64_t> out;
    unsigned idle = 0;
    while (idle < idle_limit) {
        drv.tick();
        if (drv.outputValid()) { out.push_back(drv.outputData()); idle = 0; }
        else                   { ++idle; }
    }
    return out;
}

static bool xofWaitBusyLow(SharmonyDriver& drv, unsigned limit) {
    for (unsigned i = 0; i < limit; ++i) { drv.tick(); if (!drv.busy()) return true; }
    return false;
}

// Stop mid-squeeze, observe the held residue, then resume WITHOUT a start:
// the copied+resumed words must be the exact uninterrupted stream prefix
// (no duplicate, no gap), the drain depth must match the boundary depth,
// and output_valid must then fall and STAY low (no revival).
static bool scenarioXofSqueezeStopResidue(SharmonyDriver& drv, Mode m) {
    const auto msg = xofPatternMsg(24, 0x5A);
    const size_t kTake = 5;   // words the host copies before stopping
    int fails = 0;

    // reference: uninterrupted squeeze
    xofStartSqueeze(drv, m, msg);
    const auto ref = drv.collectBeats(kTake + 8);
    drv.setOutReady(false);
    if (!xofWaitBusyLow(drv, 200)) {
        std::cerr << "[interface] xof_squeeze_stop: ref busy stuck\n";
        return false;
    }

    xofStartSqueeze(drv, m, msg);
    const auto taken = drv.collectBeats(kTake);   // host copies kTake words
    drv.setOutReady(false);                       // stop on the copy cycle
    if (!xofWaitBusyLow(drv, 200)) {
        std::cerr << "[interface] xof_squeeze_stop: busy stuck after stop\n";
        return false;
    }

    const bool     residue_valid = drv.outputValid();
    const uint64_t residue_data  = drv.outputData();

    // idle must be quiet: residue may be present but must not change.
    for (int i = 0; i < 20; ++i) {
        drv.tick();
        if (drv.outputValid() != residue_valid ||
            (residue_valid && drv.outputData() != residue_data)) {
            std::cerr << "[interface] xof_squeeze_stop: residue changed "
                      << "during idle\n";
            ++fails; break;
        }
    }

    drv.setOutReady(true);                        // resume WITHOUT start
    const auto tail = xofDrainWhileValid(drv, 30);

    // Host-ledger continuity: for a self-consistent post-edge sampling host,
    // copied words + resumed words == exact uninterrupted stream prefix. The
    // idle residue on the bus must be the last host-copied word (the beat
    // whose valid&&ready edge the DUT never saw); the resume edge consumes it
    // and the bus advances, so the host's next sample is the following word.
    if (residue_valid) {
        if (residue_data != ref[kTake - 1]) {
            std::cerr << "[interface] xof_squeeze_stop: idle residue is not "
                      << "the held stream word\n";
            ++fails;
        }
        std::vector<uint64_t> ledger = taken;
        ledger.insert(ledger.end(), tail.begin(), tail.end());
        bool cont_ok = ledger.size() <= ref.size();
        for (size_t i = 0; cont_ok && i < ledger.size(); ++i)
            cont_ok = (ledger[i] == ref[i]);
        if (!cont_ok) {
            std::cerr << "[interface] xof_squeeze_stop: copied+resumed stream "
                      << "diverges from the uninterrupted reference "
                      << "(duplicate or gap)\n";
            ++fails;
        }
        // Exact residue depth: this mid-rate stop leaves the boundary full,
        // so exactly THREE words drain DUT-side (the offered beat + two
        // staged look-ahead words); a post-edge-sampling host nets exactly
        // 2 new samples after the residue it already copied. A count change
        // here means the output boundary depth changed.
        if (tail.size() != 2) {
            std::cerr << "[interface] xof_squeeze_stop: expected exactly 2 "
                      << "post-resume samples (3 drained words), got "
                      << tail.size() << "\n";
            ++fails;
        }
    } else if (!tail.empty()) {
        std::cerr << "[interface] xof_squeeze_stop: no residue advertised but "
                  << tail.size() << " beat(s) drained\n";
        ++fails;
    }

    // After the drain the engine must stay dead until the next start.
    for (int i = 0; i < 30; ++i) {
        drv.tick();
        if (drv.outputValid()) {
            std::cerr << "[interface] xof_squeeze_stop: output_valid revived "
                      << "while idle\n";
            ++fails; break;
        }
    }
    return fails == 0;
}

// Zeroize must clear the held residue: valid falls, bus zeroed.
static bool scenarioXofSqueezeStopZeroize(SharmonyDriver& drv, Mode m) {
    xofStartSqueeze(drv, m, xofPatternMsg(24, 0x5A));
    (void)drv.collectBeats(5);
    drv.setOutReady(false);
    if (!xofWaitBusyLow(drv, 200)) {
        std::cerr << "[interface] xof_squeeze_stop: busy stuck (zeroize)\n";
        return false;
    }
    if (!drv.outputValid()) return true;   // no residue (REG_IO=0): vacuous

    drv.setZeroize(true); drv.tick(); drv.setZeroize(false);
    if (!xofWaitBusyLow(drv, 64)) {
        std::cerr << "[interface] xof_squeeze_stop: zeroize stuck\n";
        return false;
    }
    if (drv.outputValid() || drv.outputData() != 0) {
        std::cerr << "[interface] xof_squeeze_stop: zeroize left residue\n";
        return false;
    }
    return true;
}

// A new start must clear the residue: the next operation's output stream
// carries no stale beat and is bit-exact.
static bool scenarioXofSqueezeStopStart(SharmonyDriver& drv, Mode m) {
    xofStartSqueeze(drv, m, xofPatternMsg(24, 0x5A));
    (void)drv.collectBeats(5);
    drv.setOutReady(false);
    if (!xofWaitBusyLow(drv, 200)) {
        std::cerr << "[interface] xof_squeeze_stop: busy stuck (start)\n";
        return false;
    }
    const uint64_t stale       = drv.outputData();
    const bool     had_residue = drv.outputValid();

    const auto msg2 = xofPatternMsg(24, 0xC3);
    xofStartSqueeze(drv, m, msg2);             // fresh op, residue must die
    const auto out2 = drv.collectBeats(3);
    drv.setOutReady(false);
    if (!xofWaitBusyLow(drv, 200)) {
        std::cerr << "[interface] xof_squeeze_stop: busy stuck (start,2)\n";
        return false;
    }

    // reference for msg2
    xofStartSqueeze(drv, m, msg2);
    const auto ref2 = drv.collectBeats(3);
    drv.setOutReady(false);
    if (!xofWaitBusyLow(drv, 200)) {
        std::cerr << "[interface] xof_squeeze_stop: busy stuck (start,3)\n";
        return false;
    }

    if (out2 != ref2) {
        std::cerr << "[interface] xof_squeeze_stop: post-residue operation "
                  << "output corrupt\n";
        return false;
    }
    if (had_residue && out2[0] == stale && ref2[0] != stale) {
        std::cerr << "[interface] xof_squeeze_stop: stale residue leaked "
                  << "into next op\n";
        return false;
    }
    return true;
}


//-------------------------------------------------------------------------------------
//  Combined input+output stress: aggressive input gaps with output
//  backpressure in one transaction.  This is skipped for SHAKE/XOF by caller.
//-------------------------------------------------------------------------------------
static bool scenarioCombinedInputOutputStress(SharmonyDriver& drv, const ModeCase& mc) {
    const auto vec = findVector(mc, {512, 256, 128, 64}, true);
    const auto exp = expectedPrefixForMode(mc.mode, vec);
    const std::vector<unsigned> gaps = {3, 0, 8, 1, 0, 6, 2, 0, 11};

    drv.reset();
    drv.setMode(mc.mode);
    drv.setOutReady(true);
    drv.pulseStart();
    if (!sendMessageWithGaps(drv, mc.mode, vec.msg, gaps)) return false;

    drv.setOutReady(false);
    if (!drv.waitOutputValid(6000)) {
        std::cerr << "[interface] combined_input_output_stress [" << modeName(mc.mode)
                  << "]: output_valid timeout\n";
        drv.setOutReady(true);
        return false;
    }

    const uint64_t stable = drv.outputData();
    for (int i = 0; i < 7; ++i) {
        if (!drv.outputValid() || drv.outputData() != stable) {
            std::cerr << "[interface] combined_input_output_stress [" << modeName(mc.mode)
                      << "]: output not stable under backpressure\n";
            drv.setOutReady(true);
            return false;
        }
        drv.tick();
    }

    drv.setOutReady(true);
    std::vector<uint64_t> beats;
    if (!collectBeatsReadyValid(drv, digestBeatsFor(mc.mode), beats)) return false;
    return digestMatchesMode(mc.mode, beats, exp, "combined_input_output_stress");
}

//-------------------------------------------------------------------------------------
//  Transaction chaining: two legal transactions back-to-back without an intervening
//  reset.  This catches stale-state or busy/ready transition issues.
//-------------------------------------------------------------------------------------
// For SHAKE/XOF, a transaction does not naturally terminate after a fixed
// digest length.  For the back-to-back and cross-family interface checks,
// consume and verify two output beats, then drive output_ready low to stop the
// XOF stream before the next pulseStart().
static bool finishShakeProbeAndStop(SharmonyDriver& drv,
                                    const ModeCase& mc,
                                    const std::vector<uint8_t>& expected,
                                    const std::string& context) {
    constexpr size_t kShakeProbeBeats = 2;
    constexpr size_t kShakeProbeBytes = kShakeProbeBeats * 8;

    std::vector<uint64_t> beats;
    if (!collectBeatsReadyValid(drv, kShakeProbeBeats, beats)) {
        std::cerr << "[interface] " << context << " [" << modeName(mc.mode)
                  << "]: failed to collect two SHAKE output beats\n";
        drv.setOutReady(true);
        return false;
    }

    const auto expected_probe = firstBytes(expected, kShakeProbeBytes);
    if (!digestMatchesMode(mc.mode, beats, expected_probe, context)) {
        drv.setOutReady(true);
        return false;
    }

    // In SHAKE/XOF mode, deasserting output_ready in CORE_OUTPUT is the explicit
    // stop condition used here to terminate the XOF stream before the next hash.
    drv.setOutReady(false);
    drv.tick();
    drv.tick();
    drv.setOutReady(true);
    waitCycles(drv, 2);
    return true;
}

static bool scenarioShakeBackToBackTransactions(SharmonyDriver& drv, const ModeCase& mc) {
    const auto vec_a = findVector(mc, {24, 0, 8, 64}, false);
    const auto vec_b = findVector(mc, {256, 128, 64}, true);
    const auto exp_a = expectedPrefixForMode(mc.mode, vec_a);
    const auto exp_b = expectedPrefixForMode(mc.mode, vec_b);

    drv.reset();
    drv.setMode(mc.mode);
    drv.setOutReady(true);
    drv.pulseStart();
    if (!sendMessageWithGaps(drv, mc.mode, vec_a.msg, {})) return false;
    if (!finishShakeProbeAndStop(drv, mc, exp_a, "back_to_back_A")) return false;

    drv.setMode(mc.mode);
    drv.setOutReady(true);
    drv.pulseStart();
    if (!sendMessageWithGaps(drv, mc.mode, vec_b.msg, {1, 0, 2})) return false;
    if (!finishShakeProbeAndStop(drv, mc, exp_b, "back_to_back_B")) return false;

    return true;
}

static bool scenarioBackToBackTransactions(SharmonyDriver& drv, const ModeCase& mc) {
    if (modeIsShake(mc.mode)) {
        return scenarioShakeBackToBackTransactions(drv, mc);
    }

    const auto vec_a = findVector(mc, {24, 0, 8, 64}, false);
    const auto vec_b = findVector(mc, {256, 128, 64}, true);
    const auto exp_a = expectedPrefixForMode(mc.mode, vec_a);
    const auto exp_b = expectedPrefixForMode(mc.mode, vec_b);

    std::vector<uint64_t> beats;
    if (!runTransaction(drv, mc, vec_a, {}, beats, true)) return false;
    if (!digestMatchesMode(mc.mode, beats, exp_a, "back_to_back_A")) return false;

    drv.setMode(mc.mode);
    drv.setOutReady(true);
    drv.pulseStart();
    if (!sendMessageWithGaps(drv, mc.mode, vec_b.msg, {1, 0, 2})) return false;
    beats.clear();
    if (!collectBeatsReadyValid(drv, digestBeatsFor(mc.mode), beats)) return false;
    return digestMatchesMode(mc.mode, beats, exp_b, "back_to_back_B");
}

//-------------------------------------------------------------------------------------
// back_to_back_stressed_first: two consecutive hashes where the FIRST is
// stressed with BOTH input-valid gaps AND sustained output-ready back-pressure
// (forcing the skid / u_data output stages to back up), then a second hash
// starts back-to-back on the first idle cycle. Both digests must be correct --
// this catches any residue a stalled/back-pressured first op might leave behind
// (un-drained output buffers, stale FSM/counter state) that would corrupt the
// next op. (SHAKE excluded by the caller: its output back-pressure is
// intentionally unsupported.)
//-------------------------------------------------------------------------------------
static bool scenarioBackToBackStressedFirst(SharmonyDriver& drv, const ModeCase& mc) {
    const auto vec_a = findVector(mc, {256, 128, 64}, true);
    const auto vec_b = findVector(mc, {24, 64, 0, 8}, false);
    const auto exp_a = expectedPrefixForMode(mc.mode, vec_a);
    const auto exp_b = expectedPrefixForMode(mc.mode, vec_b);
    const std::vector<unsigned> gaps_a = {2, 0, 5, 1, 0, 3};

    //---------------------------------------------------------------------------------
    //  Hash 1: input-valid gaps + output-ready back-pressure
    //---------------------------------------------------------------------------------
    drv.reset();
    drv.setMode(mc.mode);
    drv.setOutReady(true);
    drv.pulseStart();
    if (!sendMessageWithGaps(drv, mc.mode, vec_a.msg, gaps_a)) return false;

    // Hold output_ready low across the first valid word (back the skid/u_data
    // up), keep it low a few cycles, then release and drain.
    drv.setOutReady(false);
    if (!drv.waitOutputValid(6000)) {
        std::cerr << "[interface] back_to_back_stressed_first [" << modeName(mc.mode)
                  << "]: hash-1 output_valid timeout\n";
        drv.setOutReady(true);
        return false;
    }
    for (int i = 0; i < 6; ++i) drv.tick();   // sustained back-pressure
    drv.setOutReady(true);

    std::vector<uint64_t> beats_a;
    if (!collectBeatsReadyValid(drv, digestBeatsFor(mc.mode), beats_a)) return false;
    if (!digestMatchesMode(mc.mode, beats_a, exp_a, "b2b_stressed_first_A")) return false;

    //---------------------------------------------------------------------------------
    //  Hash 2: back-to-back (starts on the first idle cycle), clean stream
    //---------------------------------------------------------------------------------
    drv.setMode(mc.mode);
    drv.setOutReady(true);
    drv.pulseStart();
    if (!sendMessageWithGaps(drv, mc.mode, vec_b.msg, {})) return false;

    std::vector<uint64_t> beats_b;
    if (!collectBeatsReadyValid(drv, digestBeatsFor(mc.mode), beats_b)) return false;
    return digestMatchesMode(mc.mode, beats_b, exp_b, "b2b_stressed_first_B");
}

//-------------------------------------------------------------------------------------
// Directed cross-family mode switching without reset between transactions.
// This is not a 12x11 exhaustive matrix; it is an efficient transition chain
// that covers every mode at least once and covers the important directions:
// SHA-2 -> SHA-3, SHA-3 -> SHA-2, SHA-2 -> SHAKE, SHAKE -> SHA-2,
// SHA-3 -> SHAKE, SHAKE -> SHA-3, plus SHA-2 internal variant switches.
// SHAKE/XOF steps explicitly stop after two output beats before the next mode.
//-------------------------------------------------------------------------------------
static bool runModeSwitchStep(SharmonyDriver& drv,
                              const ModeCase& mc,
                              const std::string& context,
                              const std::vector<unsigned>& input_gaps) {
    const auto vec = findVector(mc, {24, 64, 0, 128}, false);
    const auto exp = expectedPrefixForMode(mc.mode, vec);

    drv.setMode(mc.mode);
    drv.setOutReady(true);
    drv.pulseStart();

    if (!sendMessageWithGaps(drv, mc.mode, vec.msg, input_gaps)) {
        std::cerr << "[interface] " << context << " [" << modeName(mc.mode)
                  << "]: failed to send message\n";
        return false;
    }

    if (modeIsShake(mc.mode)) {
        return finishShakeProbeAndStop(drv, mc, exp, context);
    }

    std::vector<uint64_t> beats;
    if (!collectBeatsReadyValid(drv, digestBeatsFor(mc.mode), beats)) {
        std::cerr << "[interface] " << context << " [" << modeName(mc.mode)
                  << "]: failed to collect digest\n";
        return false;
    }

    return digestMatchesMode(mc.mode, beats, exp, context);
}

static bool scenarioCrossFamilyModeSwitch(SharmonyDriver& drv) {
    const std::vector<Mode> chain = {
        Mode::SHA2_224,
        Mode::SHA3_224,
        Mode::SHAKE128,
        Mode::SHA2_256,
        Mode::SHA3_256,
        Mode::SHA2_384,
        Mode::SHAKE256,
        Mode::SHA3_384,
        Mode::SHA2_512,
        Mode::SHA3_512,
        Mode::SHA2_512_224,
        Mode::SHA2_512_256,
        Mode::SHAKE128,
        Mode::SHA3_256,
        Mode::SHA2_224
    };

    drv.reset();
    drv.setOutReady(true);

    for (size_t i = 0; i < chain.size(); ++i) {
        const ModeCase* mc = findModeCase(chain[i]);
        if (!mc) return false;

        const std::string from = (i == 0) ? std::string("reset")
                                          : std::string(modeName(chain[i - 1]));
        const std::string context = "cross_family_mode_switch_" +
                                    std::to_string(i) + "_" +
                                    from + "_to_" + modeName(chain[i]);

        std::cout << "[interface] " << context << "\n";

        const std::vector<unsigned> gaps = (i % 3 == 0) ? std::vector<unsigned>{0, 1}
                                         : (i % 3 == 1) ? std::vector<unsigned>{2, 0, 3}
                                                        : std::vector<unsigned>{};

        if (!runModeSwitchStep(drv, *mc, context, gaps)) return false;

        // Small separation only; no reset. This checks that busy and
        // mode/config state return cleanly after the previous transaction.
        waitCycles(drv, 1);
    }

    return true;
}

//-------------------------------------------------------------------------------------
// Undefined-mode coverage. The 4-bit MODE field defines encodings 0x0..0xD;
// the two remaining encodings 0xE and 0xF are architecturally undefined and
// must alias to SHAKE256 in every decode (cfg LUTs, SHA-3 shift mask / insert
// index, output-length decode), including through state_save / state_load.
// These checks are mode-independent, so they run once per interface run.

// Drive one native-flow hash with an arbitrary raw MODE encoding and return
// the first 16 output bytes (2 beats, the XOF default of digestBytesFor).
static std::vector<uint8_t> undefDriveRawMode(SharmonyDriver& drv,
                                              uint8_t raw_mode,
                                              const std::vector<uint8_t>& msg) {
    const int n_beats = digestBeatsFor(Mode::SHAKE256);
    const int n_bytes = digestBytesFor(Mode::SHAKE256);

    drv.reset();
    drv.setMode(static_cast<Mode>(raw_mode));
    drv.setOutReady(true);
    drv.setStateLoad(false); drv.setStateSave(false); drv.setStateCache(false);
    drv.pulseStart();
    drv.sendMessageNative(msg);
    drv.endMsg();
    auto beats = drv.collectBeats(n_beats);
    return SharmonyDriver::beatsToBytes(beats, n_bytes);
}

// Raw hash flow: DUT output under raw 0xE/0xF == SHAKE256, both against the
// software oracle. Lengths straddle the SHAKE256 rate boundary (136 bytes).
static bool scenarioUndefModeAlias(SharmonyDriver& drv, uint8_t raw) {
    const std::vector<size_t> lens = {0, 3, 135, 136, 137, 300};

    int bad = 0;
    for (size_t len : lens) {
        std::vector<uint8_t> msg(len);
        for (size_t i = 0; i < len; ++i)
            msg[i] = (uint8_t)(0xA5 ^ (i * 7) ^ raw);

        const auto ref = refHash(Mode::SHAKE256, msg, 16);
        const auto dut_undef = undefDriveRawMode(drv, raw, msg);
        const auto dut_shake = undefDriveRawMode(
            drv, (uint8_t)Mode::SHAKE256, msg);

        if (dut_undef != ref || dut_shake != ref) {
            ++bad;
            std::cerr << "[interface] undefmode MISMATCH raw_mode=0x"
                      << std::hex << (int)raw << std::dec << " len=" << len
                      << (dut_undef != ref ? " (undef!=oracle)" : "")
                      << (dut_shake != ref ? " (shake256!=oracle)" : "")
                      << "\n";
        }
    }
    return bad == 0;
}

static constexpr size_t kUndefShakeBlock = 136;  // SHAKE256 rate (bytes)
static constexpr size_t kUndefStateBeats = 25;   // full Keccak state export

static std::vector<uint64_t> undefStateSave(SharmonyDriver& drv,
                                            uint8_t raw_mode,
                                            const std::vector<uint8_t>& prefix) {
    drv.reset();
    drv.setMode(static_cast<Mode>(raw_mode));
    drv.setOutReady(true);
    drv.setStateLoad(false);
    drv.setStateSave(true);
    drv.setStateCache(false);
    drv.pulseStart();
    drv.sendMessageNative(prefix);   // block-aligned; final triggers export
    auto res = drv.tryCollectBeats(kUndefStateBeats, 8000);
    drv.endMsg();
    return res.second;
}

static std::vector<uint64_t> undefStateResume(SharmonyDriver& drv,
                                              uint8_t raw_mode,
                                              const std::vector<uint64_t>& ms,
                                              const std::vector<uint8_t>& tail) {
    drv.reset();
    drv.setMode(static_cast<Mode>(raw_mode));
    drv.setOutReady(true);
    drv.setStateLoad(true);
    drv.setStateSave(false);
    drv.setStateCache(false);
    drv.pulseStart();
    for (uint64_t w : ms) drv.sendBeat(w, 8, 0b00);
    drv.sendMessageNative(tail);
    auto res = drv.tryCollectBeats((size_t)digestBeatsFor(Mode::SHAKE256), 8000);
    drv.endMsg();
    return res.second;
}

// State-management paths: a state_save in a raw undefined mode must export
// the full 25-lane Keccak state exactly as real SHAKE256 does (the E/F
// override sits BEFORE the state_save full-state export override), resumes
// must produce identical digests, and saves/resumes must interop with
// SHAKE256 in both directions.
static bool scenarioUndefModeState(SharmonyDriver& drv, uint8_t raw,
                                   const std::vector<uint64_t>& ms_ref,
                                   const std::vector<uint64_t>& d_ref,
                                   const std::vector<uint8_t>& prefix,
                                   const std::vector<uint8_t>& tail) {
    const uint8_t kShake256 = (uint8_t)Mode::SHAKE256;
    int bad = 0;
    auto expect = [&](bool ok, const char* what) {
        if (!ok) {
            ++bad;
            std::cerr << "[interface] undefmode_state raw=0x" << std::hex
                      << (int)raw << std::dec << ": " << what << "\n";
        }
    };

    const auto ms_raw = undefStateSave(drv, raw, prefix);
    expect(ms_raw == ms_ref, "exported mid-state differs from SHAKE256");

    const auto d_raw = undefStateResume(drv, raw, ms_raw, tail);
    expect(d_raw == d_ref, "resume digest differs from SHAKE256");

    // interop both directions
    const auto d_x1 = undefStateResume(drv, kShake256, ms_raw, tail);
    expect(d_x1 == d_ref, "SHAKE256 resume of raw-mode save differs");
    const auto d_x2 = undefStateResume(drv, raw, ms_ref, tail);
    expect(d_x2 == d_ref, "raw-mode resume of SHAKE256 save differs");

    return bad == 0;
}

static void runMergedUndefModeScenarios(SharmonyDriver& drv,
                                        IfaceScoreboard& sb) {
    std::string err;
    const bool oracle_ok = refHashSelfTest(&err);
    sb.record("undefmode_oracle_selftest", oracle_ok);
    if (!oracle_ok) {
        std::cerr << "[interface] ORACLE SELF-TEST FAILED: " << err << "\n";
        sb.skip("undefmode_alias_0xE", "oracle unavailable");
        sb.skip("undefmode_alias_0xF", "oracle unavailable");
        sb.skip("undefmode_state_0xE", "oracle unavailable");
        sb.skip("undefmode_state_0xF", "oracle unavailable");
        return;
    }

    sb.record("undefmode_alias_0xE", scenarioUndefModeAlias(drv, 0xE));
    sb.record("undefmode_alias_0xF", scenarioUndefModeAlias(drv, 0xF));

    std::vector<uint8_t> prefix(kUndefShakeBlock), tail(41);
    for (size_t i = 0; i < prefix.size(); ++i)
        prefix[i] = (uint8_t)(0x3C ^ (i * 11));
    for (size_t i = 0; i < tail.size(); ++i)
        tail[i] = (uint8_t)(0x99 + i * 7);

    const uint8_t kShake256 = (uint8_t)Mode::SHAKE256;
    const auto ms_ref = undefStateSave(drv, kShake256, prefix);
    const auto d_ref  = undefStateResume(drv, kShake256, ms_ref, tail);
    if (ms_ref.size() != kUndefStateBeats || d_ref.empty()) {
        std::cerr << "[interface] undefmode_state: SHAKE256 reference flow failed\n";
        sb.record("undefmode_state_0xE", false);
        sb.record("undefmode_state_0xF", false);
        return;
    }

    sb.record("undefmode_state_0xE",
              scenarioUndefModeState(drv, 0xE, ms_ref, d_ref, prefix, tail));
    sb.record("undefmode_state_0xF",
              scenarioUndefModeState(drv, 0xF, ms_ref, d_ref, prefix, tail));
}
}  // namespace

static int run_interface(SharmonyDriver& drv, const TestOptions& opts) {
    IfaceScoreboard sb;

    const auto cases = selectedModeCases(opts);
    if (cases.empty()) return 2;

    std::cout << "[interface] Streaming/control interface scenarios\n";
    std::cout << "[interface] Mode coverage: " << cases.size()
              << " mode(s)";
    if (!opts.mode_filter.empty()) std::cout << " filtered by --mode " << opts.mode_filter;
    std::cout << "\n";

    try {
        for (const auto& mc : cases) {
            std::cout << "[interface] === " << mc.label << " ("
                      << modeName(mc.mode) << ") ===\n";

            // 1. Reset / recovery at every point of the transaction lifecycle.
            runMergedResetScenarios(drv, mc, sb);

            // 2. Start and control acceptance (start/zeroize/mode arbitration).
            sb.record(scenarioName("start_while_busy", mc),
                      scenarioStartWhileBusy(drv, mc));
            sb.record(scenarioName("start_low_busy_high_immediate", mc),
                      scenarioStartLowBusyHighImmediate(drv, mc));
            sb.record(scenarioName("zeroize_low_busy_high_immediate", mc),
                      scenarioZeroizeLowBusyHighImmediate(drv, mc));
            sb.record(scenarioName("start_zeroize_same_cycle", mc),
                      scenarioStartZeroizeSameCycle(drv, mc));
            sb.record(scenarioName("start_at_zeroize_window_end", mc),
                      scenarioStartAtZeroizeWindowEnd(drv, mc));
            sb.record(scenarioName("mode_change_while_busy", mc),
                      scenarioModeChangeWhileBusy(drv, mc));

            // 3. Input streaming.
            sb.record(scenarioName("input_handshake", mc),
                      scenarioInputHandshake(drv, mc));
            sb.record(scenarioName("aggressive_input_gaps", mc),
                      scenarioAggressiveInputGaps(drv, mc));

            // 4. Output streaming (backpressure for hash modes, squeeze-stop
            //    for SHAKE/XOF) and combined input+output stress.
            if (modeIsShake(mc.mode)) {
                sb.skip(scenarioName("output_backpressure", mc),
                        "SHAKE/XOF output backpressure is intentionally unsupported");
                sb.skip(scenarioName("output_backpressure_every_beat", mc),
                        "SHAKE/XOF output backpressure is intentionally unsupported");
                sb.skip(scenarioName("combined_input_output_stress", mc),
                        "contains output backpressure, skipped for SHAKE/XOF");
                sb.record(scenarioName("xof_squeeze_stop_residue_drain", mc),
                          scenarioXofSqueezeStopResidue(drv, mc.mode));
                sb.record(scenarioName("xof_squeeze_stop_zeroize_clears", mc),
                          scenarioXofSqueezeStopZeroize(drv, mc.mode));
                sb.record(scenarioName("xof_squeeze_stop_start_clears", mc),
                          scenarioXofSqueezeStopStart(drv, mc.mode));
            } else {
                sb.record(scenarioName("output_backpressure", mc),
                          scenarioOutputBackpressure(drv, mc));
                sb.record(scenarioName("output_backpressure_every_beat", mc),
                          scenarioOutputBackpressureEveryBeat(drv, mc));
                sb.record(scenarioName("combined_input_output_stress", mc),
                          scenarioCombinedInputOutputStress(drv, mc));
            }

            // 5. Transaction chaining without an intervening reset.
            sb.record(scenarioName("back_to_back_transactions", mc),
                      scenarioBackToBackTransactions(drv, mc));
            if (modeIsShake(mc.mode)) {
                sb.skip(scenarioName("back_to_back_stressed_first", mc),
                        "first-op output backpressure unsupported for SHAKE/XOF");
            } else {
                sb.record(scenarioName("back_to_back_stressed_first", mc),
                          scenarioBackToBackStressedFirst(drv, mc));
            }
        }

        if (opts.mode_filter.empty()) {
            sb.record("cross_family_mode_switch", scenarioCrossFamilyModeSwitch(drv));
            runMergedUndefModeScenarios(drv, sb);
        } else {
            sb.skip("cross_family_mode_switch",
                    "requires the full mode set; skipped when MODE filter is active");
            sb.skip("undefmode_scenarios",
                    "raw-encoding checks are mode-independent; skipped when MODE filter is active");
        }
    } catch (const std::exception& e) {
        std::cerr << "[interface] exception: " << e.what() << "\n";
        sb.fail++;
    }

    std::cout << "[interface] " << sb.pass << " pass / " << sb.fail
              << " fail / " << sb.skipped << " skipped\n";
    return sb.fail == 0 ? 0 : 1;
}

REGISTER_TEST("interface", run_interface);

//-------------------------------------------------------------------------------------
//  tracewave: run ONLY the start-at-zeroize-window-end sequence (bounded, no
//  blocking) so a VCD captures exactly this scenario for the spec figures.
//  make run-tracewave VCD=1 [MODE=HASH_SHA2_256]
//-------------------------------------------------------------------------------------
static int run_tracewave(SharmonyDriver& drv, const TestOptions& opts) {
    Mode m = Mode::SHA2_256;
    if (!opts.mode_filter.empty()) {
        Mode sel;
        if (modeFromName(opts.mode_filter, sel)) m = sel;
    }

    drv.reset();
    drv.setMode(m);
    drv.setOutReady(true);
    waitCycles(drv, 2);

    // 1-cycle zeroize from idle.
    drv.setZeroize(true);
    drv.tick();
    drv.setZeroize(false);

    // Run the zeroize window: wait for busy to engage, then to the first idle.
    int guard = 0;
    while (!drv.busy() && guard++ < 16) drv.tick();
    guard = 0;
    while (drv.busy() && guard++ < 64) drv.tick();

    // Pulse start on the exact window-end (first idle) cycle.
    drv.model()->start = 1;
    drv.tick();
    drv.model()->start = 0;

    // Drive a single terminal (empty-message) beat, then run a long tail to
    // capture the full hash + digest output.
    drv.trySendBeat(0, 0, 0b11, 40);
    drv.endMsg();
    waitCycles(drv, 98);

    std::cout << "[tracewave] done mode=" << modeName(m) << "\n";
    return 0;
}

REGISTER_TEST("tracewave", run_tracewave);

//-------------------------------------------------------------------------------------
// tracewave_samecycle: run ONLY the start+zeroize-on-the-same-cycle sequence
// (bounded, no blocking) so a VCD captures exactly this scenario. Mirrors
// run_tracewave but asserts start and zeroize coincidentally (zeroize wins:
// the start is ignored, no digest is produced for it), then runs a clean
// recovery transaction to show the engine returns to a correct idle state.
//   ./Vsharmony_verilator_wrapper --test tracewave_samecycle [--mode HASH_SHA2_256]
//-------------------------------------------------------------------------------------
static int run_tracewave_samecycle(SharmonyDriver& drv, const TestOptions& opts) {
    Mode m = Mode::SHA2_256;
    if (!opts.mode_filter.empty()) {
        Mode sel;
        if (modeFromName(opts.mode_filter, sel)) m = sel;
    }

    drv.reset();
    drv.setMode(m);
    drv.setOutReady(true);
    waitCycles(drv, 2);

    // Drive start=1 and zeroize=1 so both are sampled on the SAME posedge.
    drv.model()->start = 1;
    drv.setZeroize(true);
    drv.tick();
    drv.model()->start = 0;
    drv.setZeroize(false);

    // Run the zeroize window: wait for busy to engage, then back to the first
    // idle. No output_valid should appear here (the coincident start is ignored).
    int guard = 0;
    while (!drv.busy() && guard++ < 16) drv.tick();
    guard = 0;
    while (drv.busy() && guard++ < 64) drv.tick();

    // Recovery: a clean start + single terminal (empty-message) beat + tail, to
    // show the engine runs a correct fresh transaction after the ignored start.
    drv.model()->start = 1;
    drv.tick();
    drv.model()->start = 0;
    drv.trySendBeat(0, 0, 0b11, 40);
    drv.endMsg();
    waitCycles(drv, 98);

    std::cout << "[tracewave_samecycle] done mode=" << modeName(m) << "\n";
    return 0;
}

REGISTER_TEST("tracewave_samecycle", run_tracewave_samecycle);

//-------------------------------------------------------------------------------------
// tracewave_b2b (TEMPORARY): two empty-message hashes back-to-back, no reset
// between them, with the 2nd start issued on the exact cycle busy de-asserts
// after the 1st digest -- so a VCD shows the busy->idle->start handoff.
// Defaults to SHA-256; override with --mode.
//   ./Vsharmony_verilator_wrapper --test tracewave_b2b [--mode HASH_SHA2_256]
//-------------------------------------------------------------------------------------
static int run_tracewave_b2b(SharmonyDriver& drv, const TestOptions& opts) {
    Mode m = Mode::SHA2_256;
    if (!opts.mode_filter.empty()) {
        Mode sel;
        if (modeFromName(opts.mode_filter, sel)) m = sel;
    }

    drv.reset();
    drv.setMode(m);
    drv.setOutReady(true);   // keep draining the digest so busy can de-assert
    waitCycles(drv, 2);

    for (int op = 0; op < 2; ++op) {
        // Issue start as soon as the engine is idle. On op 1 the preceding
        // while(busy) has just fallen through, so start lands on the first
        // !busy cycle -- i.e. immediately after the 1st hash finishes.
        int guard = 0;
        while (drv.busy() && guard++ < 256) drv.tick();
        drv.model()->start = 1;
        drv.tick();
        drv.model()->start = 0;

        // One terminal (empty-message) beat.
        drv.trySendBeat(0, 0, 0b11, 40);
        drv.endMsg();

        // Run compute + digest output: wait for busy to engage, then to de-assert.
        guard = 0;
        while (!drv.busy() && guard++ < 32)  drv.tick();
        guard = 0;
        while (drv.busy()  && guard++ < 256) drv.tick();
    }

    waitCycles(drv, 20);   // tail
    std::cout << "[tracewave_b2b] done mode=" << modeName(m) << "\n";
    return 0;
}

REGISTER_TEST("tracewave_b2b", run_tracewave_b2b);

//-------------------------------------------------------------------------------------
//  tracewave_hash: ONE simple hash (default SHA-224) for a clean Surfer VCD.
//  ./Vsharmony_verilator_wrapper --test tracewave_hash --vcd out.vcd
//  [--mode HASH_SHA2_256]
//  Hashes the 3-byte message "abc" (single block), drains the digest, then a
//  short tail. Bounded + small so the waveform is easy to read.
//-------------------------------------------------------------------------------------
static int run_tracewave_hash(SharmonyDriver& drv, const TestOptions& opts) {
    Mode m = Mode::SHA2_224;
    if (!opts.mode_filter.empty()) {
        Mode sel;
        if (modeFromName(opts.mode_filter, sel)) m = sel;
    }

    drv.reset();
    drv.setMode(m);
    drv.setOutReady(true);
    waitCycles(drv, 2);

    // Start when idle, then stream the short message "abc".
    int guard = 0;
    while (drv.busy() && guard++ < 64) drv.tick();
    drv.model()->start = 1;
    drv.tick();
    drv.model()->start = 0;

    const std::vector<uint8_t> msg = {'a', 'b', 'c'};
    (void)sendMessageWithGaps(drv, m, msg, {});

    // Run compute + digest output: wait for busy to engage, then de-assert.
    guard = 0; while (!drv.busy() && guard++ < 64)  drv.tick();
    guard = 0; while (drv.busy()  && guard++ < 512) drv.tick();

    waitCycles(drv, 20);   // tail
    std::cout << "[tracewave_hash] done mode=" << modeName(m) << "\n";
    return 0;
}

REGISTER_TEST("tracewave_hash", run_tracewave_hash);

//-------------------------------------------------------------------------------------
// input_handshake: run ONLY the input_valid gap scenario, so the generated VCD
// contains just the input_handshake_<mode> transaction(s). This is intended for
// the specification timing-diagram captures.
//
//   make run-input_handshake VCD=1 MODE=HASH_SHA2_512
//-------------------------------------------------------------------------------------
static int run_input_handshake(SharmonyDriver& drv, const TestOptions& opts) {
    IfaceScoreboard sb;

    const auto cases = selectedModeCases(opts);
    if (cases.empty()) return 2;

    std::cout << "[input_handshake] Message-input valid/ready handshake (input stall) scenario\n";
    std::cout << "[input_handshake] Mode coverage: " << cases.size() << " mode(s)";
    if (!opts.mode_filter.empty()) std::cout << " filtered by --mode " << opts.mode_filter;
    std::cout << "\n";

    try {
        for (const auto& mc : cases) {
            std::cout << "[input_handshake] === " << mc.label << " ("
                      << modeName(mc.mode) << ") ===\n";
            sb.record(scenarioName("input_handshake", mc),
                      scenarioInputHandshake(drv, mc));
        }
    } catch (const std::exception& e) {
        std::cerr << "[input_handshake] exception: " << e.what() << "\n";
        sb.fail++;
    }

    std::cout << "[input_handshake] " << sb.pass << " pass / " << sb.fail
              << " fail / " << sb.skipped << " skipped\n";
    return sb.fail == 0 ? 0 : 1;
}

REGISTER_TEST("input_handshake", run_input_handshake);

//-------------------------------------------------------------------------------------
// Figure-only variant of the output-backpressure drain (used ONLY by the
// run_output_handshake waveform entry below; the interface suite keeps the
// stronger every-beat scenarioOutputBackpressureEveryBeat). output_ready
// stays high for streaming acceptance, and three beats (D6, D4, D1 for
// SHA-512) take 1-, 2- and 3-cycle output_ready dips -- enough to demonstrate
// per-beat back-pressure while keeping the rendered figure compact.
//-------------------------------------------------------------------------------------
static bool scenarioOutputBackpressureWaveFig(SharmonyDriver& drv, const ModeCase& mc) {
    const auto vec = findVector(mc, {24, 0, 8, 64}, false);
    const auto exp = expectedPrefixForMode(mc.mode, vec);

    drv.reset();
    drv.setMode(mc.mode);
    drv.setOutReady(true);
    drv.pulseStart();
    if (!sendMessageWithGaps(drv, mc.mode, vec.msg, {})) return false;

    // Asymmetric per-beat back-pressure: 1-, 2- and 3-cycle output_ready
    // stalls on different beats (D6, D4, D1 for SHA-512), so the figure
    // shows the beat being held stable under three different stall widths.
    static const int kDipCycles[8] = {0, 1, 0, 2, 0, 0, 3, 0};

    std::vector<uint64_t> beats;
    beats.reserve(digestBeatsFor(mc.mode));
    for (size_t i = 0; i < digestBeatsFor(mc.mode); ++i) {
        bool seen = false;
        for (unsigned t = 0; t < 6000; ++t) {
            if (drv.outputValid()) {
                for (int h = 0; h < kDipCycles[i % 8]; ++h) {
                    drv.setOutReady(false);
                    drv.tick();
                }
                drv.setOutReady(true);
                beats.push_back(drv.outputData());
                drv.tick();
                seen = true;
                break;
            }
            drv.tick();
        }
        if (!seen) {
            std::cerr << "[output_handshake] wave figure [" << modeName(mc.mode)
                      << "]: output_valid timeout at beat " << i << "\n";
            return false;
        }
    }
    return digestMatchesMode(mc.mode, beats, exp, "output_backpressure_wave");
}

//-------------------------------------------------------------------------------------
// output_handshake: run ONLY the figure variant of the output_ready stall
// scenario, so the generated VCD contains just one compact transaction with
// three back-pressure dips (1, 2 and 3 cycles). This is intended for specification
// the specification timing-diagram captures; the exhaustive every-beat stall
// coverage lives in the interface suite (output_backpressure_every_beat).
// SHAKE/XOF modes are skipped (output backpressure intentionally unsupported).
//
//   make run-output_handshake VCD=1 MODE=HASH_SHA2_512
//-------------------------------------------------------------------------------------
static int run_output_handshake(SharmonyDriver& drv, const TestOptions& opts) {
    IfaceScoreboard sb;

    const auto cases = selectedModeCases(opts);
    if (cases.empty()) return 2;

    std::cout << "[output_handshake] Per-beat output backpressure scenario\n";
    std::cout << "[output_handshake] Mode coverage: " << cases.size() << " mode(s)";
    if (!opts.mode_filter.empty()) std::cout << " filtered by --mode " << opts.mode_filter;
    std::cout << "\n";

    try {
        for (const auto& mc : cases) {
            std::cout << "[output_handshake] === " << mc.label << " ("
                      << modeName(mc.mode) << ") ===\n";
            if (modeIsShake(mc.mode)) {
                sb.skip(scenarioName("output_backpressure_wave", mc),
                        "SHAKE/XOF output backpressure is intentionally unsupported");
                continue;
            }
            sb.record(scenarioName("output_backpressure_wave", mc),
                      scenarioOutputBackpressureWaveFig(drv, mc));
        }
    } catch (const std::exception& e) {
        std::cerr << "[output_handshake] exception: " << e.what() << "\n";
        sb.fail++;
    }

    std::cout << "[output_handshake] " << sb.pass << " pass / " << sb.fail
              << " fail / " << sb.skipped << " skipped\n";
    return sb.fail == 0 ? 0 : 1;
}

REGISTER_TEST("output_handshake", run_output_handshake);

//-------------------------------------------------------------------------------------
// duet: staggered SHA-224/256 dual-lane transaction on the split 64-bit bus.
// The hi lane carries a SHORT message that finalizes on the very first beat
// (input_final[1]=1, i.e. 2'b10) and then idles, while the lo lane keeps
// streaming a LONGER message and finalizes one beat later (input_final[0]=1,
// i.e. 2'b01). This demonstrates that the two independent 32-bit lanes
// (input_data[63:32]/[31:0], input_bytes[5:3]/[2:0], input_final[1]/[0]) run
// concurrently and finalize independently. Each lane is checked against its
// own CAVP digest. Intended for the specification timing-diagram captures.
//
//   make run-duet VCD=1 MODE=HASH_SHA2_256
//-------------------------------------------------------------------------------------
static bool scenarioDuetStaggered(SharmonyDriver& drv, const ModeCase& mc) {
    if (!modeIsDuet(mc.mode)) {
        std::cerr << "[duet] mode " << modeName(mc.mode)
                  << " is not a duet mode (use SHA2_224 / SHA2_256)\n";
        return false;
    }

    std::vector<RspVector> vectors;
    try {
        vectors = parseRsp(mc.rsp_path);
    } catch (const std::exception& e) {
        std::cerr << "[duet] RSP parse error: " << e.what() << "\n";
        return false;
    }

    const int md_len = digestBytesFor(mc.mode);

    // hi lane: 1..4 message bytes -> exactly ONE input beat, finalizes at once.
    // lo lane: 5..8 message bytes -> TWO input beats, finalizes one beat later.
    auto pick = [&](size_t lo_b, size_t hi_b) -> const RspVector* {
        for (const auto& v : vectors) {
            if (static_cast<int>(v.md.size()) >= md_len
                && v.msg.size() >= lo_b && v.msg.size() <= hi_b) return &v;
        }
        return nullptr;
    };
    const RspVector* hiv = pick(1, 4);
    const RspVector* lov = pick(5, 8);
    if (!hiv || !lov) {
        std::cerr << "[duet] " << mc.rsp_path
                  << " lacks a short(1-4B) + long(5-8B) vector pair\n";
        return false;
    }

    drv.reset();
    drv.setOutReady(true);
    drv.setMode(mc.mode);
    drv.pulseStart();
    drv.sendMessagesDuet(hiv->msg, lov->msg);
    drv.endMsg();

    // Collect the split digest. output_ready stays asserted through the
    // computation; a couple of digest beats are then deliberately held under
    // light back-pressure (output_ready low for 1-2 cycles) so the output
    // valid/ready handshake is visible in the figure, symmetric with the input
    // side. A held beat must keep output_valid asserted and its data stable.
    const size_t n_beats = digestBeatsFor(mc.mode);
    // Asymmetric per-beat back-pressure (1- and 2-cycle stalls), matching the
    // output_handshake figure's varied-stall-width motif.
    static const int kOutHold[] = {0, 1, 0, 2, 0, 0, 0, 0};
    drv.setOutReady(true);
    std::vector<uint64_t> beats;
    beats.reserve(n_beats);
    for (size_t b = 0; b < n_beats; ++b) {
        // Wait for output_valid WITHOUT consuming: sample before ticking, since
        // a tick with output_ready high would accept (and skip) the beat.
        bool seen = false;
        for (unsigned t = 0; t < 6000; ++t) {
            if (drv.outputValid()) { seen = true; break; }
            drv.tick();
        }
        if (!seen) {
            std::cerr << "[duet] output_valid timeout at beat " << b << "\n";
            drv.setOutReady(true);
            return false;
        }
        const uint64_t v = drv.outputData();
        const int hold = kOutHold[b % 8];
        if (hold > 0) {
            drv.setOutReady(false);
            for (int h = 0; h < hold; ++h) {
                if (!drv.outputValid() || drv.outputData() != v) {
                    std::cerr << "[duet] output not held stable under"
                                 " back-pressure at beat " << b << "\n";
                    drv.setOutReady(true);
                    return false;
                }
                drv.tick();
            }
            drv.setOutReady(true);
        }
        beats.push_back(v);
        drv.tick();   // accept the beat (output_ready high)
    }

    // SHA-2 streams the digest in reverse word order (H7..H0); un-reverse first.
    std::reverse(beats.begin(), beats.end());
    const auto got_hi = SharmonyDriver::beatsToHiLaneBytes(beats, md_len);
    const auto got_lo = SharmonyDriver::beatsToLoLaneBytes(beats, md_len);

    const bool ok = (got_hi == hiv->md) && (got_lo == lov->md);
    if (!ok) {
        std::cerr << "[duet] per-lane digest mismatch\n"
                  << "  hi got = " << SharmonyDriver::bytesToHex(got_hi) << "\n"
                  << "  hi exp = " << SharmonyDriver::bytesToHex(hiv->md) << "\n"
                  << "  lo got = " << SharmonyDriver::bytesToHex(got_lo) << "\n"
                  << "  lo exp = " << SharmonyDriver::bytesToHex(lov->md) << "\n";
    }
    return ok;
}

static int run_duet(SharmonyDriver& drv, const TestOptions& opts) {
    IfaceScoreboard sb;

    const auto cases = selectedModeCases(opts);
    if (cases.empty()) return 2;

    std::cout << "[duet] Staggered dual-lane (hi short / lo long) duet scenario\n";
    std::cout << "[duet] Mode coverage: " << cases.size() << " mode(s)";
    if (!opts.mode_filter.empty()) std::cout << " filtered by --mode " << opts.mode_filter;
    std::cout << "\n";

    try {
        for (const auto& mc : cases) {
            std::cout << "[duet] === " << mc.label << " ("
                      << modeName(mc.mode) << ") ===\n";
            if (!modeIsDuet(mc.mode)) {
                sb.skip(scenarioName("duet_staggered", mc),
                        "duet is SHA-224/256 only");
                continue;
            }
            sb.record(scenarioName("duet_staggered", mc),
                      scenarioDuetStaggered(drv, mc));
        }
    } catch (const std::exception& e) {
        std::cerr << "[duet] exception: " << e.what() << "\n";
        sb.fail++;
    }

    std::cout << "[duet] " << sb.pass << " pass / " << sb.fail
              << " fail / " << sb.skipped << " skipped\n";
    return sb.fail == 0 ? 0 : 1;
}

REGISTER_TEST("duet", run_duet);

//-------------------------------------------------------------------------------------
// zeroize_scrub: security test. For each representative mode, run a real hash
// so the sensitive registers are populated, hold the digest in the output regs
// (output_ready=0), then issue a zeroize and verify that EVERY sensitive
// register (core R_q/H_q/u_data/output_data_b/skid_data, pad in_data_q/
// in_bytes_q) reads back as zero after the zeroize window. Catches any
// sensitive state that survives a zeroize. Run via:  --test zeroize_scrub
//-------------------------------------------------------------------------------------
static int run_zeroize_scrub(SharmonyDriver& drv, const TestOptions& opts) {
    (void)opts;
    const std::vector<Mode> modes = {
        Mode::SHA2_256, Mode::SHA2_512, Mode::SHA3_256, Mode::SHAKE128
    };
    int fails = 0;
    for (Mode m : modes) {
        drv.reset();
        drv.setMode(m);
        drv.setOutReady(false);   // keep the digest sitting in the output regs
        waitCycles(drv, 2);

        // Multi-block, non-trivial message so R_q/H_q/in_data_q hold key/msg data.
        std::vector<uint8_t> msg(200);
        for (size_t i = 0; i < msg.size(); ++i)
            msg[i] = static_cast<uint8_t>(0x5A ^ (i * 7 + 1));

        drv.pulseStart();
        if (!sendMessageWithGaps(drv, m, msg, {})) {
            std::cerr << "[zeroize_scrub] " << modeName(m) << ": message send failed\n";
            ++fails; drv.forceIdleInputs(); continue;
        }
        // Let the final block compute and load the output registers.
        drv.waitOutputValid(4000);

        // Precondition: the hash must actually have populated sensitive state,
        // otherwise the test would pass vacuously.
        std::string nz;
        if (drv.sensitiveRegsZero(&nz)) {
            std::cerr << "[zeroize_scrub] " << modeName(m)
                      << ": PRECONDITION FAIL — all sensitive regs zero BEFORE zeroize\n";
            ++fails; drv.forceIdleInputs(); continue;
        }

        // Issue a single-cycle zeroize, then wait past the 5-cycle window.
        drv.setZeroize(true);
        drv.tick();
        drv.setZeroize(false);
        waitCycles(drv, 10);

        std::string which;
        if (!drv.sensitiveRegsZero(&which)) {
            std::cerr << "[zeroize_scrub] FAIL [" << modeName(m) << "]: '"
                      << which << "' not cleared after zeroize\n";
            ++fails;
        } else {
            std::cout << "[zeroize_scrub] OK [" << modeName(m)
                      << "] all sensitive registers cleared\n";
        }
        drv.forceIdleInputs();
    }
    return fails ? 1 : 0;
}

REGISTER_TEST("zeroize_scrub", run_zeroize_scrub);

//-------------------------------------------------------------------------------------
// oversend_duet: guards the duet input backpressure that `all_final_acked`
// provides. In a DUET op with staggered lane lengths, after BOTH lanes
// finalize the pad FSM may still sit in STREAM padding with the skid empty.
// In that window the DUT must keep input_ready LOW so a (compliant) producer
// cannot send a further beat that would leak into the hash. We simply OBSERVE
// input_ready over the post-final / pre-output window: any asserted cycle is
// an over-send hole. (input_valid stays asserted from the final beat per the
// driver convention, so an asserted ready here would also be a live transfer.)
// Run via:  --test oversend_duet
//-------------------------------------------------------------------------------------
static int oversendReadyAfterFinal(SharmonyDriver& drv, Mode m,
        const std::vector<uint8_t>& hi, const std::vector<uint8_t>& lo) {
    drv.reset();
    drv.setMode(m);
    drv.setOutReady(false);          // hold output so the window stays open
    if (!drv.tryPulseStart(500)) return -1;
    drv.sendMessagesDuet(hi, lo);    // both lanes finalized (valid stays asserted)
    int readyCycles = 0;
    for (int i = 0; i < 80 && drv.busy() && !drv.outputValid(); ++i) {
        if (drv.inputReady()) ++readyCycles;   // ready after final => over-send hole
        drv.tick();
    }
    drv.forceIdleInputs();
    return readyCycles;
}

static int run_oversend_duet(SharmonyDriver& drv, const TestOptions&) {
    auto mk = [](int n, uint8_t seed) {
        std::vector<uint8_t> v(n);
        for (int i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(seed ^ (i * 5 + 1));
        return v;
    };
    struct Case { const char* name; std::vector<uint8_t> hi, lo; };
    std::vector<Case> cases = {
        {"stagger_lo0_hi100", mk(100, 0x11), {}          },  // lo done immediately
        {"stagger_lo4_hi200", mk(200, 0x22), mk(4,  0x33)},  // lo done early, hi long
        {"stagger_lo8_hi72",  mk(72,  0x44), mk(8,  0x55)},
        {"mirror_64",         mk(64,  0x66), mk(64, 0x66)},  // both finalize together
        {"both_empty",        {},            {}          },
    };
    int fails = 0;
    for (Mode m : {Mode::SHA2_256, Mode::SHA2_224}) {
        for (auto& c : cases) {
            int r = oversendReadyAfterFinal(drv, m, c.hi, c.lo);
            bool ok = (r == 0);
            if (ok) {
                std::cout << "[oversend] OK   [" << modeName(m) << "/" << c.name
                          << "] input_ready stayed low after both finals\n";
            } else {
                std::cerr << "[oversend] FAIL [" << modeName(m) << "/" << c.name
                          << "] input_ready asserted " << r
                          << " cycle(s) after both finals (over-send hole)\n";
                ++fails;
            }
        }
    }
    std::cout << "[oversend_duet] DONE fails=" << fails << "\n";
    return fails ? 1 : 0;
}

REGISTER_TEST("oversend_duet", run_oversend_duet);

}  // namespace sharmony
