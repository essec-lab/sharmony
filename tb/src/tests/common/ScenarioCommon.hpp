///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Shared scaffolding for the scenario-based tests (error, interface,
// zeroize). Owns:
//
//   - The 12-mode sweep list (all hash/XOF modes except cSHAKE, which has
//     dedicated tests) and the mode-name <-> Mode lookup used by the
//     --mode <NAME> filter.
//   - Mode classification (sha2 / sha3 / shake / duet) so per-family
//     scenarios can be gated.
//   - Hardcoded NIST CAVS digests for the EMPTY message in every mode.
//     Used as a "recovery probe" after each scenario: any residual length
//     counter, sticky final flag, or stale word inside the DUT will
//     produce a non-matching digest immediately.
//   - The recovery-and-finalize sequence used by every scenario.
//
// The scenario tests differ only in how each individual scenario sets the
// DUT up before calling finalize:
//   reset scenarios (merged into the interface test) use the normal
//   blocking driver methods
//   error scenarios   use the try_* (non-blocking) driver methods
//
///////////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "../../SharmonyDriver.hpp"
#include "../../TestRegistry.hpp"

#include <string>
#include <vector>

namespace sharmony {

// All 12 sweep modes (cSHAKE excluded; it has dedicated tests).
extern const std::vector<Mode> kAllModes;

// Lookup by SV-style name (e.g. "HASH_SHA2_256"). Returns true on hit.
bool modeFromName(const std::string& name, Mode& out);

// Family classification.
bool modeIsSha2(Mode m);
bool modeIsSha3(Mode m);
bool modeIsShake(Mode m);
bool modeIsDuet(Mode m);

// Hardcoded NIST CAVS digest for the empty message in `m`. For SHAKE
// returns the first 16 bytes (2 64-bit beats, matching what the BFM
// collects). Returns empty vector for unknown modes.
std::vector<uint8_t> emptyDigestFor(Mode m);

// Aggregate scoreboard kept by a scenario-based test across all scenarios
// and all modes.
struct Scoreboard {
    int n_checks = 0;
    int n_fails  = 0;
    int n_warns  = 0;
    void pass() { n_checks++; }
    void fail() { n_checks++; n_fails++; }
    void warn() { n_warns++; }
};

// Apply the requested --mode filter (if any) to kAllModes. Returns the
// subset of modes to actually sweep, or an empty vector if the filter
// names an unknown mode (and prints an error in that case).
std::vector<Mode> applyModeFilter(const TestOptions& opts,
                                  const std::string& testlabel);

// Drive an empty message in the current mode. Picks mirror-mode for duet.
// Uses the blocking driver methods.
void driveEmptyMessageBlocking(SharmonyDriver& drv, Mode m);

// Drive an empty message using the non-blocking try_* methods - safe in
// the error test where the DUT may not be in a state to accept it.
// Returns true on success, false on any timeout.
bool driveEmptyMessageTry(SharmonyDriver& drv, Mode m,
                          unsigned timeout_cycles = 500);

// Stop an in-progress SHAKE/XOF squeeze. The documented STOP is out_ready LOW
// at a clock edge while in CORE_OUTPUT_XOF (-> CORE_IDLE). It must be HELD low
// and CLOCKED until the core actually leaves XOF; otherwise the engine keeps
// squeezing (busy forever). Restores out_ready high so the engine is left idle.
void shakeSqueezeStop(SharmonyDriver& drv, int max_cycles = 128);

// Compare a captured digest against an expected MD, handling the duet
// {hi_word, lo_word} layout when needed.
bool digestMatches(const std::vector<uint64_t>& beats,
                   const std::vector<uint8_t>& exp_md,
                   bool is_duet);

// Pretty-print a digest comparison failure.
void printDigestFailure(const std::string& scenario, Mode m,
                        const std::vector<uint8_t>& exp_md,
                        const std::vector<uint64_t>& got_beats);

// Recovery probe used by reset scenarios (blocking driver methods).
// Returns true if the DUT cleanly produces the correct empty digest.
bool runRecoveryCheckBlocking(SharmonyDriver& drv, Mode m,
                              const std::string& scenario);

// Recovery probe used by error scenarios (try_* methods, won't hang if
// the DUT is wedged).
bool runRecoveryCheckTry(SharmonyDriver& drv, Mode m,
                         const std::string& scenario);

// Finalize a scenario for the ERROR test: force_idle, (optionally) reset,
// force_idle, run try_* recovery, update scoreboard, print [PASS]/[FAIL].
//
//   violation_ok  the scenario's own violation check: false if the DUT
//                 ACCEPTED an illegal action (fails the scenario even when
//                 recovery succeeds).
//   reset_first   when false, the recovery hash runs WITHOUT an intervening
//                 reset -- proving the refused access left no residual
//                 state, not merely that reset scrubs it.
void finalizeErrorScenario(SharmonyDriver& drv, Mode m,
                           const std::string& scenario,
                           Scoreboard& sb,
                           bool violation_ok = true,
                           bool reset_first = true);

}  // namespace sharmony
