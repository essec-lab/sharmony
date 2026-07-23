///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// SHAKE / XOF test runners for the C++ Verilator flow.
//
// The DUT output interface has NO length field - it is a pure
// valid/ready stream of 64-bit beats. SHAKE squeezes indefinitely, so
// the *consumer* (this testbench) decides how many bits to take by
// collecting ceil(Outputlen/64) beats, truncating to Outputlen/8 bytes,
// then stopping the squeeze (reset between vectors; output_ready deassert
// in the chained and figure flows).
//
// Two NIST CAVS test families are supported:
//
//   VariableOut  (SHAKE128VariableOut.rsp, SHAKE256VariableOut.rsp)
//     Per record: COUNT / Outputlen(bits) / Msg / Output.
//     Fixed-length input, variable output length per vector. We squeeze
//     exactly Outputlen bits and compare to Output.
//
//   Monte        (SHAKE128Monte.rsp, SHAKE256Monte.rsp)
//     Header: [Minimum/Maximum Output Length (bits)].
//     One Seed (Msg), then 100 checkpoints of COUNT / Outputlen / Output.
//     The SHAKE Monte Carlo algorithm (verified against the NIST vectors):
//
//       outlen = maxOutBytes              // initial squeeze length
//       out    = seed
//       for j in 0..99:                   // 100 checkpoints
//         for i in 1..1000:
//           msg16 = leftmost 16 bytes of out (zero-padded to 16)
//           out   = SHAKE(msg16, outlen bytes)
//           rm16  = (out[outlen-2] << 8) | out[outlen-1]   // last 16 bits, BE
//           outlen= minOutBytes + (rm16 % (maxOutBytes-minOutBytes+1))
//         checkpoint j: Outputlen == len(out)*8, Output == out
//
//     Each inner SHAKE is a full DUT transaction (reset -> start -> drive
//     msg16 -> squeeze outlen bytes). The reset at the top of each inner
//     iteration is what stops the previous squeeze.
//
///////////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "../../SharmonyDriver.hpp"
#include "../../TestRegistry.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace sharmony {

// Squeeze exactly nBytes of XOF output from the DUT (must already be in a
// post-final squeezing state). Collects ceil(nBytes/8) beats and truncates.
std::vector<uint8_t> squeezeBytes(SharmonyDriver& drv, size_t nBytes,
                                  unsigned timeoutPerBeat = 4000);

// SHAKE VariableOut runner. Returns 0 pass, 1 fail, 2 setup error.
int runShakeVariableOut(SharmonyDriver& drv, const TestOptions& opts,
                        Mode mode, const std::string& default_rsp,
                        const std::string& testlabel);

// SHAKE Monte-Carlo runner. Returns 0 pass, 1 fail, 2 setup error.
int runShakeMonte(SharmonyDriver& drv, const TestOptions& opts,
                  Mode mode, const std::string& default_rsp,
                  const std::string& testlabel);

}  // namespace sharmony
