///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Zero-dependency software golden model (oracle): produces the STANDARD digest
// bytes for a message under a given mode, so a test can compare the DUT output
// against a trusted reference for arbitrary inputs (the .rsp KAT files only
// cover fixed vectors).
//
// Supported modes: SHA2_224/256/384/512/512_224/512_256, SHA3_224/256/384/512,
// SHAKE128/256. (CSHAKE is out of scope -- it needs a host-prepared N/S prefix.)
//
// Correctness is guarded by refHashSelfTest(), which checks the implementation
// against hardcoded FIPS known-answer values. A broken oracle is worse than no
// oracle, so on self-test failure the caller records a test failure and skips
// the oracle-dependent scenarios.
//
///////////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "../../SharmonyDriver.hpp"   // sharmony::Mode

#include <cstdint>
#include <string>
#include <vector>

namespace sharmony {

// Standard digest bytes of `msg` under `mode`. For the XOF modes (SHAKE) the
// output is `xof_len` bytes; xof_len is ignored for fixed-length digests.
// Throws std::runtime_error on an unsupported mode.
std::vector<uint8_t> refHash(Mode mode,
                             const std::vector<uint8_t>& msg,
                             size_t xof_len);

// True if the reference implementations reproduce the hardcoded FIPS KATs.
// On failure, *err (if non-null) describes the first mismatch.
bool refHashSelfTest(std::string* err);

}  // namespace sharmony
