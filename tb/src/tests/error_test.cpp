///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Comprehensive interface error / protocol test.
//
// Negative tests for invalid top-level usage. These are NOT KAT tests.
// They intentionally drive illegal or suspicious interface sequences
// and check that the DUT does not emit a false-valid digest, does not
// hang simulation, and can recover cleanly after reset.
//
// IMPORTANT:
//   Normal blocking driver methods (sendBeat, pulseStart) would throw
//   TimeoutError on illegal traffic because they wait for input_ready. This
//   test uses the try_* variants on SharmonyDriver, which return
//   false-on-timeout instead of throwing. A `false` return means the
//   DUT correctly refused the illegal transfer.
//
// Scenario/event numbering:
//   Generic events E1..E6 run for every mode. Duet-only events continue
//   as E7..E8 for SHA-224 / SHA-256. The log labels are intentionally
//   gap-free per mode.
//
// Per mode the test runs:
//   E1   Data beat before start
//   E2   Double pulse_start while a transaction is active
//   E3   Invalid input_bytes (>8 native, >4 per duet lane)
//        Set environment variable SKIP_E3=1 to skip.
//   E4   Mode change mid-transaction
//   E5   pulse_start before previous digest is fully drained
//   E6   zeroize asserted mid-stream
//
//   Duet add-on (SHA-224 / SHA-256 only):
//     E7   HIGH lane sends data after asserting hi_final
//     E8   LOW lane sends data after asserting lo_final
//
// Violation checks:
//   Each scenario also verifies the illegal action itself was REFUSED --
//   E1 fails if the pre-start beat is accepted, E2/E5 fail if the illegal
//   restart is accepted (busy exposed an idle window), and E4 completes
//   its transaction under hostile mode pins and requires the ORIGINAL
//   mode's digest (mode latched at start).
//
// Recovery proof:
//   After every scenario an EMPTY-message hash is run via try_* methods,
//   with the result compared against the hardcoded NIST CAVS digest for
//   the mode. E1 recovers WITHOUT an intervening reset (a refused beat
//   must leave no residual state); the other scenarios reset first. A
//   scenario PASSES iff the violation check, the output_valid check, and
//   the recovery digest all hold.
//
// Run:
//   make run-error
//   make run-error MODE=HASH_SHA2_256
//   SKIP_E3=1 make run-error
//
///////////////////////////////////////////////////////////////////////////////////////

#include "../SharmonyDriver.hpp"
#include "../TestRegistry.hpp"
#include "common/ScenarioCommon.hpp"

#include "Vsharmony_verilator_wrapper.h"   // raw start pulses in figure mode

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <vector>

namespace sharmony {

static void wait_cycles(SharmonyDriver& drv, int n) {
    for (int i = 0; i < n; i++) drv.tick();
}

// Pick a "different" mode for E4 (mode-change-mid-transaction). Falls
// back sensibly for every input mode.
static Mode pick_alternate_mode(Mode m) {
    if (m == Mode::SHA2_256) return Mode::SHA3_256;
    if (m == Mode::SHA2_224) return Mode::SHA3_224;
    if (m == Mode::SHA2_384) return Mode::SHA3_384;
    if (m == Mode::SHA2_512) return Mode::SHA3_512;
    if (m == Mode::SHA3_256) return Mode::SHA2_256;
    if (m == Mode::SHA3_224) return Mode::SHA2_224;
    if (m == Mode::SHA3_384) return Mode::SHA2_384;
    if (m == Mode::SHA3_512) return Mode::SHA2_512;
    if (m == Mode::SHAKE128) return Mode::SHAKE256;
    if (m == Mode::SHAKE256) return Mode::SHAKE128;
    if (m == Mode::SHA2_512_224) return Mode::SHA2_512_256;
    if (m == Mode::SHA2_512_256) return Mode::SHA2_512_224;
    return Mode::SHA2_256;
}

// =========================================================================
// ERROR SCENARIOS
// =========================================================================

//-------------------------------------------------------------------------------------
//  E1: Data beat before start
//-------------------------------------------------------------------------------------
// Send a data beat without a preceding pulse_start. The DUT should NOT
// accept it (input_ready stays low); trySendBeat times out.
static void e1_data_before_start(SharmonyDriver& drv, Mode m, Scoreboard& sb) {
    bool accepted;
    if (modeIsDuet(m)) {
        accepted = drv.trySendBeatDuet(0x61626300, 3, 1,
                                        0x61626300, 3, 1, 50);
    } else {
        accepted = drv.trySendBeat(0x6162630000000000ULL, 3, 0b11, 50);
    }
    drv.endMsg();
    if (accepted) {
        std::cerr << "[FAIL] E1_data_before_start [" << modeName(m)
                  << "]: DUT accepted a beat before start\n";
    }
    // No reset before the recovery hash: a correctly refused beat must have
    // left NO residual state, so recovery must succeed from here as-is.
    finalizeErrorScenario(drv, m, "E1_data_before_start", sb,
                          /*violation_ok=*/!accepted, /*reset_first=*/false);
}

//-------------------------------------------------------------------------------------
//  E2: Double pulse_start while busy
//-------------------------------------------------------------------------------------
// Two probes: (a) the polite probe -- tryPulseStart must find no idle
// window mid-transaction; (b) the RAW probe -- the start pin is pulsed
// directly while busy (a real protocol violation on the wire) and the
// transaction must still complete with the exact empty-message digest,
// proving the illegal pulse reached nothing inside the engine.
static void e2_double_start_while_busy(SharmonyDriver& drv, Mode m,
                                        Scoreboard& sb) {
    drv.tryPulseStart(200);

    // (b) RAW restart pulse right after the operation begins.
    drv.model()->start = 1;
    drv.tick();
    drv.model()->start = 0;
    bool ok = drv.busy();
    if (!ok) {
        std::cerr << "[FAIL] E2_double_start_while_busy [" << modeName(m)
                  << "]: busy dropped after raw restart pulse\n";
    }

    // (a) Polite probe: busy must never expose an idle window.
    const bool restarted = drv.tryPulseStart(50);
    if (restarted) {
        std::cerr << "[FAIL] E2_double_start_while_busy [" << modeName(m)
                  << "]: busy dropped mid-transaction; restart was accepted\n";
        ok = false;
    }

    // Complete the transaction; the digest must be untouched by the pulse.
    if (ok) {
        ok = false;
        if (driveEmptyMessageTry(drv, m)) {
            auto res = drv.tryCollectBeats(
                static_cast<size_t>(digestBeatsFor(m)), 8000);
            if (res.first) {
                std::vector<uint64_t> beats = res.second;
                if (modeIsSha2(m)) std::reverse(beats.begin(), beats.end());
                ok = digestMatches(beats, emptyDigestFor(m), modeIsDuet(m));
                if (!ok) printDigestFailure("E2_double_start_while_busy", m,
                                            emptyDigestFor(m), beats);
            } else {
                std::cerr << "[FAIL] E2_double_start_while_busy ["
                          << modeName(m)
                          << "]: digest never produced after raw restart\n";
            }
        } else {
            std::cerr << "[FAIL] E2_double_start_while_busy [" << modeName(m)
                      << "]: message not accepted after raw restart\n";
        }
    }

    wait_cycles(drv, 2);
    finalizeErrorScenario(drv, m, "E2_double_start_while_busy", sb,
                          /*violation_ok=*/ok);
}

//-------------------------------------------------------------------------------------
//  E3: Invalid input_bytes count
//-------------------------------------------------------------------------------------
// Native datapath is 64-bit => max 8 bytes. Duet lanes are 32-bit => max
// 4 bytes per lane. Drives an OOR value; export SKIP_E3=1 to skip.
static void e3_invalid_byte_count(SharmonyDriver& drv, Mode m,
                                   Scoreboard& sb) {
    if (std::getenv("SKIP_E3")) {
        std::cout << "[SKIP] E3_invalid_byte_count [" << modeName(m)
                  << "] (SKIP_E3 set)\n";
        return;
    }

    drv.tryPulseStart(200);

    if (modeIsDuet(m)) {
        drv.trySendBeatDuet(0xDEADBEEF, 5 /*illegal: >4*/, 1,
                            0x61626300, 3, 1, 100);
    } else {
        drv.trySendBeat(0xDEADBEEFCAFEBABEULL, 9 /*illegal: >8*/, 0b11, 100);
    }

    drv.endMsg();
    finalizeErrorScenario(drv, m, "E3_invalid_byte_count", sb);
}

//-------------------------------------------------------------------------------------
//  E4: Mode change while busy
//-------------------------------------------------------------------------------------
// The mode must be LATCHED at start: mutate the external mode pins right
// after the operation begins, run the transaction to completion under the
// hostile mode value, and require the digest of the ORIGINAL mode. This
// proves the mutation was ignored, not merely that reset recovers from it.
static void e4_mode_change_while_busy(SharmonyDriver& drv, Mode m,
                                       Scoreboard& sb) {
    drv.tryPulseStart(200);

    // Illegal mutation mid-transaction, before any message beat.
    drv.setMode(pick_alternate_mode(m));
    wait_cycles(drv, 2);

    // Complete an empty-message transaction with the hostile mode still
    // applied to the pins.
    bool latched = false;
    if (driveEmptyMessageTry(drv, m)) {
        std::vector<uint64_t> beats;
        const size_t n = static_cast<size_t>(digestBeatsFor(m));
        auto res = drv.tryCollectBeats(n, 8000);
        if (res.first) {
            beats = res.second;
            if (modeIsSha2(m)) std::reverse(beats.begin(), beats.end());
            latched = digestMatches(beats, emptyDigestFor(m), modeIsDuet(m));
            if (!latched) printDigestFailure("E4_mode_change_while_busy", m,
                                             emptyDigestFor(m), beats);
        } else {
            std::cerr << "[FAIL] E4_mode_change_while_busy [" << modeName(m)
                      << "]: digest never produced under hostile mode pins\n";
        }
    } else {
        std::cerr << "[FAIL] E4_mode_change_while_busy [" << modeName(m)
                  << "]: message not accepted under hostile mode pins\n";
    }
    drv.setMode(m);

    finalizeErrorScenario(drv, m, "E4_mode_change_while_busy", sb,
                          /*violation_ok=*/latched);
}

//-------------------------------------------------------------------------------------
//  E5: pulse_start before previous digest is drained
//-------------------------------------------------------------------------------------
// Uses an EMPTY message so the surviving digest can be checked against the
// hardcoded CAVP reference. Two probes while the stream is genuinely
// undrained (output_ready low for hash modes; SHAKE keeps ready high, the
// squeeze itself holds busy): (a) polite tryPulseStart must refuse, and
// (b) a RAW start pulse on the pin must leave the pending digest intact --
// every remaining beat is then collected and compared.
static void e5_start_before_output_drained(SharmonyDriver& drv, Mode m,
                                            Scoreboard& sb) {
    drv.tryPulseStart(200);

    if (!driveEmptyMessageTry(drv, m)) {
        std::cerr << "[FAIL] E5_start_before_output_drained [" << modeName(m)
                  << "]: empty message not accepted\n";
        finalizeErrorScenario(drv, m, "E5_start_before_output_drained", sb,
                              /*violation_ok=*/false);
        return;
    }

    if (!drv.waitOutputValid(4000)) {
        std::cerr << "[WARN] E5_start_before_output_drained [" << modeName(m)
                  << "]: no first output seen before restart probe\n";
        sb.warn();
    }

    bool ok = true;
    std::vector<uint64_t> beats;
    const size_t n_beats = static_cast<size_t>(digestBeatsFor(m));

    // Capture-first drain helper: sample output_data BEFORE the tick that
    // accepts the beat, so a beat already valid on entry is never lost.
    auto collect = [&](size_t want) -> bool {
        for (size_t b = 0; b < want; ++b) {
            bool seen = false;
            for (unsigned t = 0; t < 8000; ++t) {
                if (drv.outputValid()) {
                    beats.push_back(drv.outputData());
                    drv.tick();
                    seen = true;
                    break;
                }
                drv.tick();
            }
            if (!seen) return false;
        }
        return true;
    };

    if (modeIsShake(m)) {
        // SHAKE: collect the two reference beats FIRST (any probe tick with
        // ready high would consume squeeze beats), then probe mid-squeeze --
        // the ongoing squeeze holds busy high, so both probes must bounce.
        ok = collect(n_beats);
        if (!ok) {
            std::cerr << "[FAIL] E5_start_before_output_drained ["
                      << modeName(m) << "]: squeeze beats not collected\n";
        }
        // Probes run with ready HIGH: deasserting ready mid-squeeze is the
        // documented XOF STOP (engine idles, restart becomes legal), which
        // is not the violation under test. Beats consumed by the probe
        // ticks are surplus squeeze output and irrelevant -- the reference
        // beats are already collected above.
        if (drv.tryPulseStart(20)) {
            std::cerr << "[FAIL] E5_start_before_output_drained ["
                      << modeName(m) << "]: restart accepted mid-squeeze\n";
            ok = false;
        }
        drv.model()->start = 1;
        drv.tick();
        drv.model()->start = 0;
        if (!drv.busy()) {
            std::cerr << "[FAIL] E5_start_before_output_drained ["
                      << modeName(m)
                      << "]: busy dropped after raw restart mid-squeeze\n";
            ok = false;
        }
    } else {
        // Hash modes: hold the whole digest under back-pressure while both
        // probes fire, then drain and require every beat.
        drv.setOutReady(false);

        // (a) Polite probe.
        if (drv.tryPulseStart(20)) {
            std::cerr << "[FAIL] E5_start_before_output_drained ["
                      << modeName(m)
                      << "]: restart accepted while digest not drained\n";
            ok = false;
        }

        // (b) RAW restart pulse with the digest still pending.
        drv.model()->start = 1;
        drv.tick();
        drv.model()->start = 0;
        if (!drv.busy()) {
            std::cerr << "[FAIL] E5_start_before_output_drained ["
                      << modeName(m)
                      << "]: busy dropped after raw restart pulse\n";
            ok = false;
        }

        drv.setOutReady(true);
        if (ok) {
            ok = collect(n_beats);
            if (!ok) {
                std::cerr << "[FAIL] E5_start_before_output_drained ["
                          << modeName(m)
                          << "]: digest incomplete after raw restart pulse\n";
            }
        }
    }

    if (ok) {
        if (modeIsSha2(m)) std::reverse(beats.begin(), beats.end());
        ok = digestMatches(beats, emptyDigestFor(m), modeIsDuet(m));
        if (!ok) printDigestFailure("E5_start_before_output_drained", m,
                                    emptyDigestFor(m), beats);
    }
    wait_cycles(drv, 2);

    finalizeErrorScenario(drv, m, "E5_start_before_output_drained", sb,
                          /*violation_ok=*/ok);
}

//-------------------------------------------------------------------------------------
//  E6: zeroize asserted mid-stream
//-------------------------------------------------------------------------------------
// Drives a couple of legal non-final beats, then pulls the zeroize line
// HIGH for several cycles while the DUT is mid-message. The DUT is
// expected to drop the in-flight state. After releasing zeroize, the
// finalizer applies reset and runs the recovery probe to confirm the
// next operation produces the correct empty digest.
static void e6_zeroize_mid_stream(SharmonyDriver& drv, Mode m,
                                    Scoreboard& sb) {
    drv.tryPulseStart(200);

    if (modeIsDuet(m)) {
        drv.trySendBeatDuet(0x33333333, 4, 0, 0x44444444, 4, 0, 200);
        drv.trySendBeatDuet(0x55555555, 4, 0, 0x66666666, 4, 0, 200);
    } else {
        drv.trySendBeat(0x3333333344444444ULL, 8, 0, 200);
        drv.trySendBeat(0x5555555566666666ULL, 8, 0, 200);
    }

    drv.endMsg();           // drop input_valid before asserting zeroize
    drv.setZeroize(true);
    wait_cycles(drv, 6);
    drv.setZeroize(false);
    wait_cycles(drv, 2);

    finalizeErrorScenario(drv, m, "E6_zeroize_mid_stream", sb);
}


//-------------------------------------------------------------------------------------
//  E7: Duet HIGH lane sends data after hi_final
//-------------------------------------------------------------------------------------
static void e7_duet_data_after_high_final(SharmonyDriver& drv, Mode m,
                                           Scoreboard& sb) {
    drv.tryPulseStart(200);
    // Legal first beat: hi finalizes, lo still streaming.
    drv.trySendBeatDuet(0x61626300, 3, 1,    // hi final
                        0x11111111, 4, 0, 200);
    // Illegal: hi sends more bytes after final.
    drv.trySendBeatDuet(0xDEADBEEF, 4, 0,
                        0x22222222, 4, 0, 100);
    // Do not try to complete a malformed transaction.
    finalizeErrorScenario(drv, m, "E7_duet_data_after_high_final", sb);
}

//-------------------------------------------------------------------------------------
//  E8: Duet LOW lane sends data after lo_final
//-------------------------------------------------------------------------------------
static void e8_duet_data_after_low_final(SharmonyDriver& drv, Mode m,
                                          Scoreboard& sb) {
    drv.tryPulseStart(200);
    drv.trySendBeatDuet(0x11111111, 4, 0,
                        0x61626300, 3, 1, 200);   // lo final
    drv.trySendBeatDuet(0x22222222, 4, 0,
                        0xDEADBEEF, 4, 0, 100);   // illegal: lo extra data
    finalizeErrorScenario(drv, m, "E8_duet_data_after_low_final", sb);
}

// =========================================================================
// PER-MODE DISPATCHER
// =========================================================================
static void run_all_error_scenarios_for_mode(SharmonyDriver& drv, Mode m,
                                              Scoreboard& sb) {
    drv.reset();
    drv.tick();
    drv.setMode(m);
    wait_cycles(drv, 2);

    std::cout << "-----------------------------------------------------------------\n";
    std::cout << "[error] MODE=" << modeName(m)
              << "  starting error scenarios\n";
    std::cout << "-----------------------------------------------------------------\n";

    //---------------------------------------------------------------------------------
    //  Generic interface/protocol errors
    //---------------------------------------------------------------------------------
    e1_data_before_start(drv, m, sb);
    e2_double_start_while_busy(drv, m, sb);
    e3_invalid_byte_count(drv, m, sb);
    e4_mode_change_while_busy(drv, m, sb);
    e5_start_before_output_drained(drv, m, sb);
    e6_zeroize_mid_stream(drv, m, sb);

    //---------------------------------------------------------------------------------
    //  Duet-specific errors
    //---------------------------------------------------------------------------------
    if (modeIsDuet(m)) {
        e7_duet_data_after_high_final(drv, m, sb);
        e8_duet_data_after_low_final(drv, m, sb);
    }
}

// =========================================================================
// FIGURE MODE (--figure-trace)
// =========================================================================
// Renders ONE compact, self-checking trace for the hardware spec's
// "Invalid Access" figure (waveforms/error.pdf).
//
//   make run-error VCD=1    (with --figure-trace in EXTRA_ARGS)
//
// Timeline: THREE distinct invalid accesses attack one continuous
// SHA2-512 transaction, each visibly refused, and the transaction still
// finishes with the exact CAVP digest:
//   V1  data beat before start      -> input_ready/busy stay low, refused
//   V2  restart pulse + hostile mode write during compute -> ignored,
//       busy stays high, core_fsm_q runs on
//   V3  restart pulse in the middle of the digest output   -> ignored,
//       beats keep streaming
static int run_error_figure(SharmonyDriver& drv) {
    const Mode m = Mode::SHA2_512;

    drv.reset();
    drv.tick();
    drv.setMode(m);
    drv.setOutReady(true);
    wait_cycles(drv, 2);

    //---------------------------------------------------------------------------------
    //  V1: data beat before start (must be refused)
    //---------------------------------------------------------------------------------
    const bool accepted = drv.trySendBeat(0x6162630000000000ULL, 3, 0b11, 1);
    drv.endMsg();          // drop the refused beat's input_valid
    wait_cycles(drv, 1);
    if (accepted) {
        std::cerr << "[error/figure] FAIL: DUT accepted a beat before start\n";
        return 1;
    }

    //---------------------------------------------------------------------------------
    //  Legal transaction begins (no reset: the refusal left no state)
    //---------------------------------------------------------------------------------
    drv.tryPulseStart(50);
    if (!drv.trySendBeat(0, 0, 0b11, 50)) {   // empty message, final beat
        std::cerr << "[error/figure] FAIL: legal final beat not accepted\n";
        return 1;
    }
    drv.endMsg();

    //---------------------------------------------------------------------------------
    //  V2: restart pulse + hostile mode write during compute
    //---------------------------------------------------------------------------------
    drv.model()->start = 1;      // raw pulse: deliberate protocol violation
    drv.tick();
    drv.model()->start = 0;
    drv.setMode(pick_alternate_mode(m));
    wait_cycles(drv, 2);
    drv.setMode(m);
    if (!drv.busy()) {
        std::cerr << "[error/figure] FAIL: busy dropped after mid-compute restart\n";
        return 1;
    }

    //---------------------------------------------------------------------------------
    //  Digest drain with V3: restart pulse mid-output
    //---------------------------------------------------------------------------------
    std::vector<uint64_t> beats;
    for (size_t b = 0; b < 8; ++b) {
        bool seen = false;
        for (unsigned t = 0; t < 6000; ++t) {
            if (drv.outputValid()) {
                beats.push_back(drv.outputData());
                drv.tick();
                seen = true;
                break;
            }
            drv.tick();
        }
        if (!seen) {
            std::cerr << "[error/figure] FAIL: digest beat " << b << " timeout\n";
            return 1;
        }
        if (b == 1) {
            // V3: restart while six digest beats are still pending. Hold
            // output_ready low across the pulse tick so the probe itself
            // cannot silently accept (and lose) a beat.
            drv.setOutReady(false);
            drv.model()->start = 1;
            drv.tick();
            drv.model()->start = 0;
            drv.setOutReady(true);
            if (!drv.busy()) {
                std::cerr << "[error/figure] FAIL: busy dropped after mid-output restart\n";
                return 1;
            }
        }
    }

    std::reverse(beats.begin(), beats.end());   // SHA-2 emits H7..H0
    if (!digestMatches(beats, emptyDigestFor(m), false)) {
        printDigestFailure("error_figure", m, emptyDigestFor(m), beats);
        return 1;
    }

    std::cout << "[error/figure] PASS: three invalid accesses refused, "
                 "digest exact\n";
    return 0;
}

// =========================================================================
// ENTRY POINT
// =========================================================================
static int run_error(SharmonyDriver& drv, const TestOptions& opts) {
    if (opts.figure_trace) return run_error_figure(drv);

    auto modes = applyModeFilter(opts, "error");
    if (modes.empty()) return 2;

    std::cout << "=================================================================\n";
    std::cout << ">>> error test starting\n";
    std::cout << "    modes_to_run=" << modes.size();
    if (!opts.mode_filter.empty())
        std::cout << "  (filter=" << opts.mode_filter << ")";
    if (std::getenv("SKIP_E3"))
        std::cout << "  (E3 disabled via SKIP_E3)";
    std::cout << "\n";
    std::cout << "=================================================================\n";

    Scoreboard sb;
    for (Mode m : modes) run_all_error_scenarios_for_mode(drv, m, sb);

    std::cout << "-----------------------------------------------------------------\n";
    std::cout << "[error] DONE  (checks=" << sb.n_checks
              << "  fails=" << sb.n_fails;
    if (sb.n_warns) std::cout << "  warns=" << sb.n_warns;
    std::cout << ")\n";

    return (sb.n_fails == 0) ? 0 : 1;
}

REGISTER_TEST("error", run_error);

}  // namespace sharmony
