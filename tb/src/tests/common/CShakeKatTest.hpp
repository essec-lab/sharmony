///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// cSHAKE KAT runner (NIST SP 800-185).
//
// cSHAKE differs from SHAKE only in:
//   - domain suffix: 0x04 (instead of SHAKE's 0x1F)
//   - a bytepad(encode_string(N) || encode_string(S), rate) preamble that is
//     prepended to the message before streaming
//
// The preamble is constructed here in software and concatenated with the
// message; the hardware sees one continuous beat stream.
//
// Vectors are loaded from a cSHAKE .rsp file (N/S/MsgLen/Msg/OutputLen/Output);
// see RspParser::parseRspCShake. The number of output beats compared is derived
// from each vector's OutputLen.
//
///////////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "../../SharmonyDriver.hpp"
#include "../../TestRegistry.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace sharmony {

// Build bytepad(encode_string(N) || encode_string(S), rate_bytes).
// rate_bytes = 168 for cSHAKE128, 136 for cSHAKE256.
std::vector<uint8_t> cshake_preamble(unsigned rate_bytes,
                                      const std::string& N,
                                      const std::string& S);

// Load cSHAKE vectors from default_rsp (overridable via opts.rsp_path) and run
// them against the DUT in the given mode. Executes two phases (reset-per-vector,
// then single-reset-chain) and prints a summary. Returns 0 on all-pass.
int runCShakeKat(SharmonyDriver& drv,
                 const TestOptions& opts,
                 Mode mode,
                 const std::string& default_rsp,
                 const std::string& testlabel);

}  // namespace sharmony
