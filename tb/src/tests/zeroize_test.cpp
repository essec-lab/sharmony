///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Dedicated zeroization test - C++ Verilator flow.   Run: make run-zeroize
//
// SECURITY / robustness tests for the `zeroize` line, distinct from
// error_test.cpp (which only pokes zeroize post-endMsg and recovers via reset()).
//
// DESIGN: reset() is applied ONCE per mode. After that the scenarios CHAIN -
// the only thing that returns the engine to a usable state between scenarios is
// zeroize itself plus the natural end-of-hash return-to-idle. We never reset
// between a zeroize and the recovery hash; that is the whole point. A reset is
// used only as a last-resort safety net if the engine is found genuinely stuck
// (ensureIdle), and that fallback is logged as a failure.
//
// Why chaining matters: a per-scenario reset would scrub any state a FAULTY
// zeroize left behind, hiding exactly the bug we want to catch (stale state -
// e.g. the H_q gap - leaking into the next operation).
//
// Scenarios (per mode, where applicable):
//   Z1  Run a real hash (leaves residue), then idle-zeroize, recover (no reset)
//   Z2a Zeroize during the SHA-2 input/W-load phase (input_valid high mid-stream)
//   Z2  Zeroize mid-FSM-phase, ordered SHA-2 -> SHA-3 -> SHAKE:
//       Z2b ABSORB (SHA-3 in) / Z2c ROUNDS / Z2d OUTPUT_HASH / Z2e OUTPUT_XOF (SHAKE)
//   Z3  Single-cycle zeroize pulse vs the multi-cycle hold
//   Z4  Zeroize during SHAKE squeeze / XOF output (SHAKE only)
//   Z5a Zeroize coincident with start (zeroize||start priority)         [start]
//   Z5b Zeroize mid input-stall (input_ready low); probe in_data_q/in_bytes_q [input]
//   Z5c Zeroize while output_valid && !out_ready (backpressured output)  [output]
//   Z6  Back-to-back / repeated zeroize pulses
//   Z7  Multi-block message: zeroize during an INTERMEDIATE block (real midstate)
//   Z8  WHITEBOX scrub: probe H_q/R_q/in_data_q/in_bytes_q/output_data + exact hold
//   Z9  Busy-immediate from post-hash idle: one-cycle zeroize pulse after a
//       completed hash must raise busy on the exact cycle the pulse ends (no
//       busy gap), then the window runs and the residual state is verified
//       scrubbed
//   Z10 Zeroize destroys the INTERNAL CACHE SLOT (H_q single-slot cache):
//       cache-save, zeroize, cache-resume must NOT reproduce the real digest,
//       and the engine must keep hashing correctly (all SHA-2 modes: 64-bit
//       family native, SHA-224/256 duet-mirror; migrated from the midstate
//       corner batch)
//
// IMPORTANT on interpreting results: a passing recovery digest proves FUNCTIONAL
// recovery, not scrubbing - a fresh hash reloads its own IV and will compute
// correctly even over un-scrubbed registers. Only Z8 and Z9 (and the
// in_data_q/in_bytes_q probes in Z5b) prove the security scrub.
//
// All stimulus uses the non-throwing try* driver methods so a stuck DUT is
// reported as a FAIL instead of hanging the simulation.
//
///////////////////////////////////////////////////////////////////////////////////////

#include "../SharmonyDriver.hpp"
#include "../TestRegistry.hpp"
#include "common/ScenarioCommon.hpp"

#include "Vsharmony_verilator_wrapper.h"
#include "Vsharmony_verilator_wrapper___024root.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace sharmony {
namespace {

// essec_sharmony_pkg::core_fsm_e (authoritative values from essec_sharmony_pkg.sv).
enum CoreFsm : uint8_t {
    CF_IDLE = 0, CF_INIT = 1, CF_ROUNDS = 2, CF_NEXT = 3, CF_WAIT = 4,
    CF_ZEROIZE = 5, CF_ABSORB = 6, CF_OUTPUT_HASH = 7, CF_SHA3_INIT = 8,
    CF_OUTPUT_XOF = 9
};

static const char* fsmName(uint8_t s) {
    switch (s) {
        case CF_IDLE: return "IDLE";          case CF_INIT: return "INIT";
        case CF_ROUNDS: return "ROUNDS";      case CF_NEXT: return "NEXT";
        case CF_WAIT: return "WAIT";          case CF_ZEROIZE: return "ZEROIZE";
        case CF_ABSORB: return "ABSORB";      case CF_OUTPUT_HASH: return "OUTPUT_HASH";
        case CF_SHA3_INIT: return "SHA3_INIT";case CF_OUTPUT_XOF: return "OUTPUT_XOF";
        default: return "INVALID";
    }
}

// core_fsm_q is public_flat_rd (same path the performance test uses).
static uint8_t readCoreFsm(SharmonyDriver& drv) {
    const auto* top = drv.model();
    return static_cast<uint8_t>(
        top->rootp->sharmony_verilator_wrapper__DOT__dut__DOT__core_inst__DOT__core_fsm_q);
}

// Read the active-zeroize window via the top-level `zeroize_sub` probe. This
// equals zeroize_active (REG_IO=1) / zeroize_active_q (REG_IO=0) and is a
// top-level signal, so the path is the same in both configs.
static bool readZeroizeActive(SharmonyDriver& drv) {
    const auto* top = drv.model();
    return top->rootp
        ->sharmony_verilator_wrapper__DOT__dut__DOT__zeroize_sub;
}

static bool waitZeroizeInactive(SharmonyDriver& drv, unsigned max_cycles, unsigned& waited) {
    waited = 0;
    while (readZeroizeActive(drv)) {
        if (waited >= max_cycles) return false;
        drv.tick();
        ++waited;
    }
    return true;
}

// Pad input-skid probes. Require these markers in sharmony_pad.sv:
//     logic [63:0] in_data_q  /* verilator public_flat_rd */;
//     logic [5:0]  in_bytes_q /* verilator public_flat_rd */;
// Used by Z5b (mid-stall scrub) and Z8 (whitebox scrub).
static uint64_t readInDataQ(SharmonyDriver& drv) {
    const auto* top = drv.model();
    return top->rootp
        ->sharmony_verilator_wrapper__DOT__dut__DOT__pad_inst__DOT__in_data_q;
}
static uint8_t readInBytesQ(SharmonyDriver& drv) {
    const auto* top = drv.model();
    return static_cast<uint8_t>(top->rootp
        ->sharmony_verilator_wrapper__DOT__dut__DOT__pad_inst__DOT__in_bytes_q);
}

// Local scoreboard (self-contained; mirrors interface_test's style).
struct ZScore {
    int pass = 0, fail = 0, skip = 0;
    void record(const std::string& name, bool ok) {
        if (ok) { pass++; std::cout << "[PASS] [zeroize] " << name << "\n"; }
        else    { fail++; std::cerr << "[FAIL] [zeroize] " << name << "\n"; }
    }
    void skipped(const std::string& name, const std::string& why) {
        skip++; std::cout << "[SKIP] [zeroize] " << name << " -- " << why << "\n";
    }
    void fail_msg(const std::string& name, const std::string& why) {
        fail++; std::cerr << "[FAIL] [zeroize] " << name << " -- " << why << "\n";
    }
};

static void waitCycles(SharmonyDriver& drv, int n) {
    for (int i = 0; i < n; ++i) drv.tick();
}

// Compare collected beats to an expected digest (SHA-2 reverse; duet mirror).
static bool digestMatchesMode(Mode m, std::vector<uint64_t> beats,
                              const std::vector<uint8_t>& exp) {
    if (modeIsSha2(m)) std::reverse(beats.begin(), beats.end());
    return digestMatches(beats, exp, modeIsDuet(m));
}

// Drive one empty message (non-hanging) and finalize.
static bool sendEmptyTry(SharmonyDriver& drv, Mode m, unsigned to = 500) {
    bool sent = modeIsDuet(m) ? drv.trySendBeatDuet(0, 0, 1, 0, 0, 1, to)
                              : drv.trySendBeat(0, 0, 0b11, to);
    drv.endMsg();
    return sent;
}

// Feed a short single-block message ("abc") via non-hanging sends.
static bool feedAbcTry(SharmonyDriver& drv, Mode m, unsigned to = 500) {
    bool ok = modeIsDuet(m) ? drv.trySendBeatDuet(0x61626300, 3, 1, 0x61626300, 3, 1, to)
                            : drv.trySendBeat(0x6162630000000000ULL, 3, 0b11, to);
    drv.endMsg();
    return ok;
}

// Feed `n` nonzero, NON-final, full-width beats (no endMsg). Leaves input_valid
// high with the last beat on the bus (driver convention). Used to keep the
// input stream live mid-message (Z2a), cross block boundaries (Z7), and latch
// real data into the pad skid before a stall (Z5b). Returns false if a beat is
// refused within the timeout.
static bool feedFullBeatsNonFinal(SharmonyDriver& drv, Mode m, int n, unsigned to = 1000) {
    for (int k = 0; k < n; ++k) {
        const bool ok = modeIsDuet(m)
            ? drv.trySendBeatDuet(0x11223344u, 4, 0, 0x55667788u, 4, 0, to)
            : drv.trySendBeat(0x1122334455667788ULL, 8, 0b00, to);
        if (!ok) return false;
    }
    return true;
}

// Run one full hash to completion (loads + drains), leaving real residue in the
// state registers and the engine idle. Non-hanging.
static void runOneHash(SharmonyDriver& drv, Mode m) {
    drv.setOutReady(true);
    if (!drv.tryPulseStart(500)) return;
    feedAbcTry(drv, m);
    drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000);
    if (modeIsShake(m)) shakeSqueezeStop(drv);   // actually stop the XOF -> idle
}

// THE recovery check: with NO reset, start a fresh empty hash and verify it.
static bool recoverNoReset(SharmonyDriver& drv, Mode m,
                           const std::string& ctx, ZScore& sb) {
    drv.setOutReady(true);
    if (!drv.tryPulseStart(500)) {
        sb.fail_msg(ctx, "accept_start never re-asserted (busy stuck) after zeroize");
        return false;
    }
    if (!sendEmptyTry(drv, m)) {
        sb.fail_msg(ctx, "input never accepted on recovery hash");
        return false;
    }
    auto res = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000);
    if (!res.first) {
        if (modeIsShake(m)) shakeSqueezeStop(drv);
        sb.fail_msg(ctx, "digest never produced on recovery hash (timeout)");
        return false;
    }
    if (modeIsShake(m)) shakeSqueezeStop(drv);   // stop the XOF so the engine idles
    const bool ok = digestMatchesMode(m, res.second, emptyDigestFor(m));
    sb.record(ctx + " :: recovery-no-reset digest", ok);
    return ok;
}

// Between scenarios: confirm the engine returned to idle on its own. Only if it
// is genuinely stuck do we fall back to a reset (logged as a failure) so the
// remaining scenarios still run. No reset on the happy path.
static void ensureIdle(SharmonyDriver& drv, Mode m,
                       const std::string& ctx, ZScore& sb) {
    drv.setOutReady(true);
    for (int i = 0; i < 128; ++i) {
        if (drv.acceptStart()) return;          // !busy -> idle
        drv.tick();
    }
    sb.fail_msg(ctx, "engine still busy entering scenario; forcing reset to continue");
    drv.reset();
    drv.setMode(m);
    waitCycles(drv, 2);
}

// =========================================================================
// Z1  Real hash leaves residue -> idle zeroize -> recover (no reset).
// =========================================================================
static void z1_idle_zeroize_then_hash(SharmonyDriver& drv, Mode m, ZScore& sb) {
    ensureIdle(drv, m, "Z1_idle_zeroize", sb);

    runOneHash(drv, m);          // leave real residue in H_q/R_q, engine idle

    drv.setZeroize(true);
    waitCycles(drv, 1);
    drv.setZeroize(false);
    waitCycles(drv, 2);

    recoverNoReset(drv, m, "Z1_idle_zeroize_after_hash", sb);
}

// =========================================================================
// Z2  Zeroize while the core is in a specific FSM phase, then recover.
// =========================================================================
static void z2_zeroize_in_phase(SharmonyDriver& drv, Mode m, uint8_t target,
                                 int hold, const std::string& label, ZScore& sb) {
    ensureIdle(drv, m, label, sb);

    if (!drv.tryPulseStart(500)) { sb.fail_msg(label, "pulseStart timed out"); return; }
    if (!feedAbcTry(drv, m))     { sb.fail_msg(label, "input refused"); return; }

    bool reached = false;
    for (int i = 0; i < 3000; ++i) {
        if (readCoreFsm(drv) == target) { reached = true; break; }
        drv.tick();
    }
    if (!reached) {
        sb.skipped(label, fsmName(target) + std::string(" state not observed for this mode"));
        drv.setOutReady(true);
        for (int i = 0; i < 64 && readCoreFsm(drv) != CF_IDLE; ++i) drv.tick();
        if (modeIsShake(m)) shakeSqueezeStop(drv);
        return;
    }

    const uint8_t at = readCoreFsm(drv);
    drv.setZeroize(true);
    waitCycles(drv, hold);
    drv.setZeroize(false);
    waitCycles(drv, 2);

    std::cout << "[zeroize] " << label << ": zeroize asserted in "
              << fsmName(at) << " state\n";
    recoverNoReset(drv, m, label, sb);
}

// =========================================================================
// Z2a Zeroize during the SHA-2 input / W-load phase (input_valid high
//     mid-stream). SHA-3's input phase is ABSORB and is covered by Z2b; the
//     SHA-2 input path is distinct (W schedule load while streaming), so it
//     leads the Z2 group (SHA-2 -> SHA-3 -> SHAKE). SHA-2 modes only.
// =========================================================================
static void z2a_zeroize_sha2_input(SharmonyDriver& drv, Mode m, ZScore& sb) {
    const std::string label = "Z2a_zeroize_in_SHA2_INPUT";
    if (!modeIsSha2(m)) {
        sb.skipped(label, "SHA-2-only (SHA-3 input is ABSORB, see Z2b)");
        return;
    }

    ensureIdle(drv, m, label, sb);

    if (!drv.tryPulseStart(500)) { sb.fail_msg(label, "pulseStart timed out"); return; }

    // A few non-final beats -> mid W-load, input_valid still asserted.
    if (!feedFullBeatsNonFinal(drv, m, 3)) {
        sb.fail_msg(label, "input refused mid-stream");
        drv.endMsg();
        return;
    }

    const uint8_t at = readCoreFsm(drv);
    const bool iv = (drv.model()->input_valid != 0);

    drv.setZeroize(true);            // zeroize WITH the input stream live
    waitCycles(drv, 1);
    drv.setZeroize(false);
    drv.endMsg();                    // drop the held beat
    waitCycles(drv, 2);

    std::cout << "[zeroize] " << label << ": zeroize asserted with input_valid="
              << (iv ? 1 : 0) << " in " << fsmName(at) << " state\n";
    recoverNoReset(drv, m, label, sb);
}

// =========================================================================
// Z3  Single-cycle zeroize pulse vs multi-cycle hold.
// =========================================================================
static void z3_pulse_width(SharmonyDriver& drv, Mode m, int hold,
                           const std::string& label, ZScore& sb) {
    ensureIdle(drv, m, label, sb);

    if (!drv.tryPulseStart(500)) { sb.fail_msg(label, "pulseStart timed out"); return; }
    feedAbcTry(drv, m);
    for (int i = 0; i < 8 && readCoreFsm(drv) == CF_IDLE; ++i) drv.tick();

    drv.setZeroize(true);
    waitCycles(drv, hold);       // hold == 1 tests the single-cycle assert
    drv.setZeroize(false);
    waitCycles(drv, 2);

    recoverNoReset(drv, m, label, sb);
}

// =========================================================================
// Z4  Zeroize during SHAKE squeeze / XOF output (SHAKE only).
// =========================================================================
static void z4_zeroize_during_squeeze(SharmonyDriver& drv, Mode m, ZScore& sb) {
    const std::string label = "Z4_zeroize_during_squeeze";
    if (!modeIsShake(m)) { sb.skipped(label, "XOF squeeze is SHAKE-only"); return; }

    ensureIdle(drv, m, label, sb);

    if (!drv.tryPulseStart(500)) { sb.fail_msg(label, "pulseStart timed out"); return; }
    feedAbcTry(drv, m);

    if (!drv.waitOutputValid(8000)) { sb.fail_msg(label, "no XOF output before zeroize"); return; }
    drv.tick(); drv.tick();                  // squeeze a little
    drv.setZeroize(true);
    waitCycles(drv, 1);
    drv.setZeroize(false);
    drv.setOutReady(true);
    waitCycles(drv, 2);

    recoverNoReset(drv, m, label, sb);
}

// =========================================================================
// Z5a Zeroize coincident with start (zeroize||start priority).   [start]
// =========================================================================
static void z5a_zeroize_with_start(SharmonyDriver& drv, Mode m, ZScore& sb) {
    const std::string label = "Z5a_zeroize_coincident_start";
    ensureIdle(drv, m, label, sb);

    // Drive start AND zeroize into the same rising edge. zeroize must win.
    auto* top = drv.model();
    top->zeroize = 1;
    top->start   = 1;
    drv.tick();
    top->start   = 0;
    waitCycles(drv, 1);
    top->zeroize = 0;
    drv.setZeroize(false);
    waitCycles(drv, 2);

    recoverNoReset(drv, m, label, sb);
}

// =========================================================================
// Z5b Zeroize while the INPUT side is mid-stall (a beat is held with
//     input_ready low). Verifies the pad input skid is scrubbed: in_data_q
//     and in_bytes_q must read 0 after the zeroize window closes.   [input]
// =========================================================================
static void z5b_zeroize_input_stall(SharmonyDriver& drv, Mode m, ZScore& sb) {
    const std::string label = "Z5b_zeroize_input_stall";
    ensureIdle(drv, m, label, sb);

    if (!drv.tryPulseStart(500)) { sb.fail_msg(label, "pulseStart timed out"); return; }

    // Latch real (nonzero) data into the pad skid first.
    if (!feedFullBeatsNonFinal(drv, m, 2)) {
        sb.fail_msg(label, "input refused");
        drv.endMsg();
        return;
    }

    // Hold a nonzero, non-final beat on the bus and wait for the pad to stall
    // (input_ready low) while the core digests what it already has.
    auto* top = drv.model();
    if (modeIsDuet(m)) {
        top->input_data  = (static_cast<uint64_t>(0x11223344u) << 32) | 0x55667788u;
        top->input_bytes = (4 << 3) | 4;
    } else {
        top->input_data  = 0x1122334455667788ULL;
        top->input_bytes = 8;
    }
    top->input_valid = 1;
    top->input_final = 0;
    top->eval();

    for (int i = 0; i < 128; ++i) {
        if (!drv.inputReady()) break;   // mid-stall reached (or beat fully held)
        drv.tick();                     // ready high -> keep transferring/latching
    }

    // Zeroize on top of the held input beat (input_valid still high).
    drv.setZeroize(true);
    waitCycles(drv, 1);
    drv.setZeroize(false);
    drv.endMsg();                // release the held beat so nothing re-latches

    unsigned waited = 0;
    waitZeroizeInactive(drv, 32, waited);

    sb.record(label + " :: in_data_q scrubbed",  readInDataQ(drv) == 0);
    sb.record(label + " :: in_bytes_q scrubbed", readInBytesQ(drv) == 0);

    recoverNoReset(drv, m, label, sb);
}

// =========================================================================
// Z5c Zeroize while output is backpressured (output_valid && !out_ready). [output]
// =========================================================================
static void z5c_zeroize_backpressured_output(SharmonyDriver& drv, Mode m, ZScore& sb) {
    const std::string label = "Z5c_zeroize_backpressured_output";
    ensureIdle(drv, m, label, sb);

    if (!drv.tryPulseStart(500)) { sb.fail_msg(label, "pulseStart timed out"); return; }
    feedAbcTry(drv, m);

    drv.setOutReady(false);                  // backpressure the output
    if (!drv.waitOutputValid(8000)) { sb.fail_msg(label, "output never valid under backpressure"); return; }

    drv.setZeroize(true);                    // zeroize on top of a held, unaccepted beat
    waitCycles(drv, 1);
    drv.setZeroize(false);
    drv.setOutReady(true);
    waitCycles(drv, 2);

    recoverNoReset(drv, m, label, sb);
}

// =========================================================================
// Z6  Back-to-back / repeated zeroize pulses.
// =========================================================================
static void z6_repeated_zeroize(SharmonyDriver& drv, Mode m, ZScore& sb) {
    const std::string label = "Z6_repeated_zeroize";
    ensureIdle(drv, m, label, sb);

    for (int k = 0; k < 4; ++k) {
        drv.setZeroize(true);  drv.tick();
        drv.setZeroize(false); drv.tick();
    }
    waitCycles(drv, 4);
    recoverNoReset(drv, m, label, sb);
}

// =========================================================================
// Z7  Multi-block message: zeroize during an INTERMEDIATE block.
//
// Every other scenario uses single-block "abc". Here we stream more than one
// full block of non-final beats so the core has actually absorbed/compressed
// at least one intermediate block (real midstate now lives in H_q/R_q), then
// zeroize BEFORE the final block. 24 beats exceeds the largest rate (SHAKE128
// = 21 beats/block), so a block boundary is crossed for every mode.
// =========================================================================
static void z7_zeroize_intermediate_block(SharmonyDriver& drv, Mode m, ZScore& sb) {
    const std::string label = "Z7_zeroize_intermediate_block";
    ensureIdle(drv, m, label, sb);

    if (!drv.tryPulseStart(500)) { sb.fail_msg(label, "pulseStart timed out"); return; }

    if (!feedFullBeatsNonFinal(drv, m, 24)) {
        sb.fail_msg(label, "input refused before crossing a block boundary");
        drv.endMsg();
        return;
    }

    const uint8_t at = readCoreFsm(drv);
    drv.setZeroize(true);            // mid intermediate block, input stream live
    waitCycles(drv, 1);
    drv.setZeroize(false);
    drv.endMsg();
    waitCycles(drv, 2);

    std::cout << "[zeroize] " << label << ": zeroize mid intermediate block in "
              << fsmName(at) << " state\n";
    recoverNoReset(drv, m, label, sb);
}

// Expected zeroize_active hold after a single-cycle zeroize pulse, counted
// from the cycle the pulse DEASSERTS (Z8's sampling convention: assert,
// waitCycles(1), deassert, then start counting). This is ZEROIZE_IDX + 1 = 5
// in the current RTL and was confirmed empirically (Z8 also prints the live
// count). Z8 asserts the measured hold equals this EXACTLY - if you change
// the pulse/sampling sequence or ZEROIZE_IDX, update this constant.
static constexpr unsigned kZeroizeHoldCycles = 5;

// =========================================================================
// Z8  WHITEBOX scrub assertion.
//
// Requires these markers in hw/sharmony/essec_sharmony_pad.sv (read-only debug
// visibility; dead-code-eliminated by synthesis - no functional change):
//     logic [63:0] in_data_q  /* verilator public_flat_rd */;
//     logic [5:0]  in_bytes_q /* verilator public_flat_rd */;
//
// Requires these markers in hw/sharmony/essec_sharmony_core.sv (read-only debug
// visibility; dead-code-eliminated by synthesis - no functional change):
//     logic [63:0] R_q [0:24]   /* verilator public_flat_rd */;
//     logic [63:0] H_q [0:7]    /* verilator public_flat_rd */;
//
// (output_data is read via the top-level port, so no marker is needed for it.)
// =========================================================================
static bool allZeroR(SharmonyDriver& drv, int& first_nz) {
    const auto* top = drv.model();
    const auto& R = top->rootp->sharmony_verilator_wrapper__DOT__dut__DOT__core_inst__DOT__R_q;
    for (int i = 0; i < 25; ++i) if (R[i] != 0) { first_nz = i; return false; }
    return true;
}
static bool allZeroH(SharmonyDriver& drv, int& first_nz) {
    const auto* top = drv.model();
    const auto& H = top->rootp->sharmony_verilator_wrapper__DOT__dut__DOT__core_inst__DOT__H_q;
    for (int i = 0; i < 8; ++i) if (H[i] != 0) { first_nz = i; return false; }
    return true;
}

static uint64_t readOutB(SharmonyDriver& drv) {
    return drv.model()->output_data;
}

static void z8_whitebox_scrub(SharmonyDriver& drv, Mode m, ZScore& sb) {
    const std::string label = "Z8_whitebox_scrub";
    ensureIdle(drv, m, label, sb);

    if (!drv.tryPulseStart(500)) { sb.fail_msg(label, "pulseStart timed out"); return; }
    feedAbcTry(drv, m);
    for (int i = 0; i < 200 && readCoreFsm(drv) != CF_OUTPUT_HASH
                            && readCoreFsm(drv) != CF_OUTPUT_XOF; ++i) drv.tick();

    drv.setZeroize(true);
    waitCycles(drv, 1);
    const bool zeroize_seen_active = readZeroizeActive(drv);
    drv.setZeroize(false);

    if (!zeroize_seen_active) {
        sb.fail_msg(label, "zeroize_active did not assert after zeroize pulse");
        return;
    }

    unsigned zeroize_waited = 0;
    if (!waitZeroizeInactive(drv, 32, zeroize_waited)) {
        sb.fail_msg(label, "zeroize_active stayed high after 32 cycles");
        return;
    }
    std::cout << "[zeroize] " << label << ": zeroize_active cleared after "
            << zeroize_waited << " cycles\n";

    // Strict window check: the hold must be EXACTLY ZEROIZE_IDX + 1 cycles,
    // not merely within the 32-cycle liveness bound used above.
    sb.record(label + " :: zeroize_active hold == "
                    + std::to_string(kZeroizeHoldCycles) + " cycles",
              zeroize_waited == kZeroizeHoldCycles);

    int nz = -1;
    if (!allZeroR(drv, nz)) sb.fail_msg(label, "R_q[" + std::to_string(nz) + "] != 0 after zeroize");
    else                    sb.record(label + " :: R_q scrubbed", true);

    nz = -1;
    if (!allZeroH(drv, nz)) sb.fail_msg(label, "H_q[" + std::to_string(nz)
                                               + "] != 0 after zeroize (suspected H_q gap)");
    else                    sb.record(label + " :: H_q scrubbed", true);

    const uint64_t in_data_q = readInDataQ(drv);
    if (in_data_q != 0) sb.fail_msg(label, "in_data_q != 0 after zeroize");
    else                sb.record(label + " :: in_data_q scrubbed", true);

    const uint8_t in_bytes_q = readInBytesQ(drv);
    if (in_bytes_q != 0) sb.fail_msg(label, "in_bytes_q != 0 after zeroize");
    else                 sb.record(label + " :: in_bytes_q scrubbed", true);

    sb.record(label + " :: output_data scrubbed", readOutB(drv) == 0);

    // Leave the engine idle for the next scenario/mode.
    ensureIdle(drv, m, label, sb);
}

// =========================================================================
// Z9  Busy-immediate from post-hash idle: after a completed hash (residual
//     state in the registers, engine idle), a one-cycle zeroize pulse must
//     raise busy on the exact cycle the pulse ends. No cycle may exist with
//     zeroize=0 && busy=0: in that gap a host reads "zeroization done"
//     before the wipe has begun, or slips in a start that the wipe then
//     destroys.
//     Complements interface_test's zeroize_low_busy_high_immediate (which
//     runs from post-reset idle): here the registers hold residual state,
//     so the from-idle wipe itself is also verified end-to-end.
// =========================================================================
static void z9_busy_immediate_post_hash_idle(SharmonyDriver& drv, Mode m, ZScore& sb) {
    const std::string label = "Z9_busy_immediate_post_hash_idle";
    ensureIdle(drv, m, label, sb);

    runOneHash(drv, m);          // real residue in H_q/R_q, engine idle

    // Drain to idle first: tryCollectBeats returns on the last digest beat,
    // while the core is still stepping back to IDLE (visible with REG_IO=0's
    // combinational busy). The strict timing check is after the pulse, not here.
    for (int i = 0; i < 64 && drv.busy(); ++i) drv.tick();
    if (drv.busy()) {
        sb.fail_msg(label, "engine never returned to idle after the hash");
        return;
    }

    // One-cycle pulse, post-edge placement; the busy check happens on the
    // exact cycle the pulse ends -- no extra tick is allowed before it.
    drv.setZeroize(true);
    drv.tick();
    drv.setZeroize(false);

    sb.record(label + " :: busy high on the cycle the pulse ends", drv.busy());

    // The zeroize window must then run and release.
    unsigned waited = 0;
    if (!waitZeroizeInactive(drv, 32, waited)) {
        sb.fail_msg(label, "zeroize_active stayed high after 32 cycles");
        return;
    }
    for (int i = 0; i < 8 && drv.busy(); ++i) drv.tick();
    if (drv.busy()) {
        sb.fail_msg(label, "busy stuck after the zeroize window");
        return;
    }

    // The residue must actually be gone: the from-idle wipe is real, not a
    // no-op on already-clear registers.
    int nz = -1;
    if (!allZeroR(drv, nz)) sb.fail_msg(label, "R_q[" + std::to_string(nz)
                                               + "] != 0 after idle zeroize");
    else                    sb.record(label + " :: R_q scrubbed", true);

    nz = -1;
    if (!allZeroH(drv, nz)) sb.fail_msg(label, "H_q[" + std::to_string(nz)
                                               + "] != 0 after idle zeroize");
    else                    sb.record(label + " :: H_q scrubbed", true);

    recoverNoReset(drv, m, label, sb);
}

// =========================================================================
// Z10  Zeroize destroys the INTERNAL CACHE SLOT (single-slot H_q cache).
//      cache-save a block-aligned prefix (silent, slot stays in H_q),
//      zeroize, cache-resume the tail: the digest must NOT match
//      hash(prefix||tail) -- the slot is dead -- and the engine must keep
//      hashing correctly afterwards (chained, no reset). All SHA-2 modes,
//      native and duet (the cache is SHA-2-only). Migrated from the
//      midstate corner batch.
// =========================================================================
static void z10_zeroize_kills_cache_slot(SharmonyDriver& drv, Mode m, ZScore& sb) {
    const std::string label = std::string("Z10_cache_slot [") + modeName(m) + "]";
    ensureIdle(drv, m, label, sb);

    // duet modes (SHA-224/256): 64 B/lane block, mirror stimulus on both lanes.
    const bool   duet   = modeIsDuet(m);
    const size_t blkLen = duet ? 64 : 128;
    std::vector<uint8_t> prefix(blkLen), tail(37);
    for (size_t i = 0; i < prefix.size(); ++i) prefix[i] = uint8_t(i * 3 + 7);
    for (size_t i = 0; i < tail.size(); ++i)   tail[i]   = uint8_t(0x5A ^ i);
    std::vector<uint8_t> full = prefix; full.insert(full.end(), tail.begin(), tail.end());

    auto settle = [&]() { for (int i = 0; i < 2000 && drv.busy(); ++i) drv.tick(); };
    auto send = [&](const std::vector<uint8_t>& msg) {
        if (duet) drv.sendMessageDuetMirror(msg); else drv.sendMessageNative(msg);
    };
    auto hashNR = [&](const std::vector<uint8_t>& msg) {
        drv.setMode(m); drv.setOutReady(true);
        drv.setStateLoad(false); drv.setStateSave(false); drv.setStateCache(false);
        std::vector<uint64_t> d;
        if (drv.tryPulseStart(500)) {
            send(msg); drv.endMsg();
            d = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000).second;
        }
        settle();
        return d;
    };

    auto d_ok = hashNR(full);
    if (d_ok.empty()) { sb.fail_msg(label, "oracle hash failed"); return; }

    // cache-save the prefix (silent; slot lives in H_q, so NO reset from here).
    drv.setMode(m); drv.setOutReady(true);
    drv.setStateCache(true); drv.setStateSave(true); drv.setStateLoad(false);
    if (!drv.tryPulseStart(500)) { sb.fail_msg(label, "cache-save start refused"); return; }
    send(prefix); drv.endMsg();
    drv.setStateSave(false);
    settle();

    // kill the slot
    drv.setZeroize(true); waitCycles(drv, 1); drv.setZeroize(false);
    waitCycles(drv, 2);
    settle();

    // cache-resume: must NOT reproduce the real digest.
    drv.setStateCache(true); drv.setStateLoad(true); drv.setStateSave(false);
    std::vector<uint64_t> dz;
    if (drv.tryPulseStart(500)) {
        send(tail); drv.endMsg();
        dz = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000).second;
    }
    drv.setStateLoad(false); drv.setStateCache(false);
    settle();

    sb.record(label + " :: slot killed", !(dz.size() == d_ok.size() && dz == d_ok));

    // chained recovery: the engine must still hash correctly, no reset.
    auto d2 = hashNR(full);
    sb.record(label + " :: recovery", d2.size() == d_ok.size() && d2 == d_ok);
}

// =========================================================================
// PER-MODE DISPATCHER  -- ONE reset here; scenarios chain after it.
// =========================================================================
static void run_all_zeroize_for_mode(SharmonyDriver& drv, Mode m, ZScore& sb) {
    std::cout << "-----------------------------------------------------------------\n";
    std::cout << "[zeroize] MODE=" << modeName(m) << "  starting scenarios\n";
    std::cout << "-----------------------------------------------------------------\n";

    drv.reset();                 // the ONLY scheduled reset (per mode)
    drv.setMode(m);
    drv.setOutReady(true);
    waitCycles(drv, 2);

    z1_idle_zeroize_then_hash(drv, m, sb);

    z2a_zeroize_sha2_input(drv, m, sb);                                          // SHA-2 input
    z2_zeroize_in_phase(drv, m, CF_ABSORB,      1, "Z2b_zeroize_in_ABSORB", sb); // SHA-3 input
    z2_zeroize_in_phase(drv, m, CF_ROUNDS,      1, "Z2c_zeroize_in_ROUNDS", sb);
    z2_zeroize_in_phase(drv, m, CF_OUTPUT_HASH, 1, "Z2d_zeroize_in_OUTPUT_HASH", sb);
    if (modeIsShake(m))
        z2_zeroize_in_phase(drv, m, CF_OUTPUT_XOF, 1, "Z2e_zeroize_in_OUTPUT_XOF", sb); // SHAKE

    z3_pulse_width(drv, m, 1, "Z3a_zeroize_pulse_1cycle", sb);
    z3_pulse_width(drv, m, 5, "Z3b_zeroize_hold_5cycle",  sb);

    z4_zeroize_during_squeeze(drv, m, sb);

    // Z5 group, ordered start -> input -> output.
    z5a_zeroize_with_start(drv, m, sb);
    z5b_zeroize_input_stall(drv, m, sb);
    z5c_zeroize_backpressured_output(drv, m, sb);

    z6_repeated_zeroize(drv, m, sb);

    z7_zeroize_intermediate_block(drv, m, sb);

    z8_whitebox_scrub(drv, m, sb);

    z9_busy_immediate_post_hash_idle(drv, m, sb);

    // internal cache slot is SHA-2-only (native + duet families).
    if (modeIsSha2(m))
        z10_zeroize_kills_cache_slot(drv, m, sb);
}

// =========================================================================
// Figure waveform sequence (Z8 + Z5c hybrid, bounded, no scoreboard).
//
// Renders ONE compact zeroize transaction for the hardware specification:
// a real single-block hash populates H_q/R_q/output regs, the first digest
// beat is frozen on the bus under output backpressure (nonzero CSP clearly
// visible), then a single-cycle zeroize pulse opens the kZeroizeHoldCycles
// zeroize_sub window and every bus collapses to zero.
//
//   make run-zeroize VCD=1 MODE=HASH_SHA2_512   (or MODE=HASH_SHA3_256)
// =========================================================================
static int run_zeroize_wave(SharmonyDriver& drv, Mode m) {
    std::cout << "[zeroize] figure waveform sequence  mode=" << modeName(m) << "\n";

    drv.reset();
    drv.setMode(m);
    drv.setOutReady(true);
    waitCycles(drv, 2);

    // 1) Real single-block hash so H_q/R_q and the output regs hold live data.
    if (!drv.tryPulseStart(500)) {
        std::cerr << "[zeroize] wave: pulseStart timed out\n";
        return 1;
    }
    feedAbcTry(drv, m);

    // 2) Run to the output phase: the digest is now driven on output_data.
    for (int i = 0; i < 400 && readCoreFsm(drv) != CF_OUTPUT_HASH
                            && readCoreFsm(drv) != CF_OUTPUT_XOF; ++i) drv.tick();

    // 3) Backpressure (Z5c flavor): freeze the first digest beat on the bus
    //    (output_valid=1, output_ready=0) so a nonzero CSP is unambiguously
    //    visible for several rendered cycles before the scrub.
    drv.setOutReady(false);
    waitCycles(drv, 4);

    // 4) Single-cycle zeroize pulse -> zeroize_sub holds kZeroizeHoldCycles.
    drv.setZeroize(true);
    waitCycles(drv, 1);
    drv.setZeroize(false);

    unsigned held = 0;
    if (!waitZeroizeInactive(drv, 32, held)) {
        std::cerr << "[zeroize] wave: zeroize_sub stuck high\n";
        return 1;
    }
    std::cout << "[zeroize] wave: zeroize_sub held " << held
              << " cycles (expected " << kZeroizeHoldCycles << ")\n";

    // 5) Tail: release out_ready, show the scrubbed buses and the return to IDLE.
    drv.setOutReady(true);
    waitCycles(drv, 3);
    return (held == kZeroizeHoldCycles) ? 0 : 1;
}

// =========================================================================
// ENTRY POINT
// =========================================================================
static int run_zeroize(SharmonyDriver& drv, const TestOptions& opts) {
    auto modes = applyModeFilter(opts, "zeroize");
    if (modes.empty()) return 2;

    if (opts.figure_trace) {
        return run_zeroize_wave(drv, modes.front());
    }

    std::cout << "=================================================================\n";
    std::cout << ">>> zeroize test starting   modes_to_run=" << modes.size();
    if (!opts.mode_filter.empty()) std::cout << "  (filter=" << opts.mode_filter << ")";
    std::cout << "  (WHITEBOX scrub probe ON)";
    std::cout << "\n";
    std::cout << "=================================================================\n";

    ZScore sb;
    for (Mode m : modes) run_all_zeroize_for_mode(drv, m, sb);

    std::cout << "-----------------------------------------------------------------\n";
    std::cout << "[zeroize] DONE  pass=" << sb.pass
              << "  fail=" << sb.fail << "  skip=" << sb.skip << "\n";
    return (sb.fail == 0) ? 0 : 1;
}

REGISTER_TEST("zeroize", run_zeroize);

}  // namespace
}  // namespace sharmony
