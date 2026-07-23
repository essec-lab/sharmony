///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Cross-lane (duet-mode) KAT runner. Loads the standard NIST .rsp file for
// the mode (e.g. SHA256ShortMsg.rsp) and PAIRS the vectors against each
// other on the two lanes.
//
//   "mid" scheme (always built):
//     pair k  =>  hi = vec[k],            lo = vec[half + k]
//     for k in [0, half), where half = n_vectors / 2.
//
// Swap adds reversed pairs, Full adds swap + targeted (shortest, longest)
// pairs. All schemes exercise asymmetric duet traffic and require the DUT
// to support independent lane finalization.
//
// Per pair we run TWO checks (one per lane). A partial-fail pair is
// reported as 1 fail of 2 in the global tally.
//
// Current SHA2-32 duet restriction: this runner keeps only KAT vectors with
// Len <= 440 bits, so each lane's SHA-256/SHA-224 padding can finish in one
// compression block. The Len=0 vector is intentionally kept.
//
///////////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "../../SharmonyDriver.hpp"
#include "../../TestRegistry.hpp"
#include <string>

namespace sharmony {

int runDuetXLaneKat(SharmonyDriver& drv,
                    const TestOptions& opts,
                    Mode mode,
                    const std::string& default_rsp,
                    const std::string& testlabel);

}  // namespace sharmony
