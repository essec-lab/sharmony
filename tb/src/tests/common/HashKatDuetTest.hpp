///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Duet-mode KAT runner for SHA-224 / SHA-256 on the duet build of the DUT.
//
// Driving:
//   The DUT runs SHA-256 (or SHA-224) as TWO independent 32-bit lanes in
//   parallel. This helper drives the SAME message on hi and lo lanes
//   (mirror mode), so both lanes independently compute the same digest.
//   That gives single-vector KAT coverage on the duet datapath.
//
// Output (per the DUT contract):
//   beat[i][63:32] = hi-lane 32-bit digest word i (big-endian)
//   beat[i][31:0]  = lo-lane 32-bit digest word i
//   SHA-256 -> 8 beats, SHA-224 -> 7 beats.
//
// Comparison:
//   Strict per-lane: every output beat must carry the expected MD word in
//   BOTH lanes ({md, md}); any lane mismatch fails the vector.
//
///////////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "../../SharmonyDriver.hpp"
#include "../../TestRegistry.hpp"
#include <string>

namespace sharmony {

int runHashKatDuet(SharmonyDriver& drv,
                   const TestOptions& opts,
                   Mode mode,
                   const std::string& default_rsp,
                   const std::string& testlabel);

}  // namespace sharmony
