///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// NIST Monte Carlo runner.
//
// SHA-2 ("3-message sliding window"):
//   Seed = MD[-1] = MD[-2] = MD[-3] = seed_from_rsp
//   For j in 0..99:
//     For i in 0..999:
//       Mi  = MD[i-3] || MD[i-2] || MD[i-1]
//       MDi = SHA(Mi)
//     Seed = MD[999]
//     MD[-1..-3] = MD[999] for next checkpoint
//     Compare against MDj from .rsp
//
// SHA-3 ("simple chain"):
//   Seed = MD[0] = seed_from_rsp
//   For j in 0..99:
//     For i in 1..1000:
//       MDi = SHA3(MD[i-1])
//     Seed = MD[1000]
//     Compare against MDj from .rsp
//
// Note: the .rsp Monte file has "Seed = <hex>" followed by 100 checkpoint
// MDs in COUNT=0..99 entries; parseRspMonte() returns the seed and the
// checkpoint list directly.
//
///////////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "../../SharmonyDriver.hpp"
#include "../../TestRegistry.hpp"
#include <string>

namespace sharmony {

enum class MonteFamily { Sha2, Sha3 };

int runMonte(SharmonyDriver& drv,
             const TestOptions& opts,
             Mode mode,
             MonteFamily family,
             const std::string& default_rsp,
             const std::string& testlabel);

}  // namespace sharmony
