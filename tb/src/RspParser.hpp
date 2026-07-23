///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// NIST/CAVP-style hash test vector file (.rsp) parser.
//
// Recognizes the common fields:
//   Len = <int>    -- message length in BITS
//   Msg = <hex>    -- message bytes in hex (one line per beat is fine here
//                     because the .rsp files use a single line)
//   MD  = <hex>    -- expected digest in hex
//   Output = <hex> -- SHAKE XOF output (used by the SHAKE tests)
//
// A vector ends when MD (or Output) is seen; the next Len starts a new vector.
//
// Conventions handled:
//   - Len = 0 with Msg = 00 represents the EMPTY message, not the byte 0x00.
//   - Non-byte-aligned Len values (Len % 8 != 0) are reported as parse-time
//     errors; they are not supported by the byte-granular DUT interface.
//   - Section headers like "[L = 64]" and comments starting with "#" are
//     ignored.
//
///////////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sharmony {

struct RspVector {
    int                   len_bits = 0;  // from Len = ...
    std::vector<uint8_t>  msg;           // empty if len_bits == 0
    std::vector<uint8_t>  md;            // from MD = ... (or Output = ...)
};

// NIST Monte Carlo .rsp files have a different structure than ShortMsg/
// LongMsg: a single "Seed = ..." line followed by 100 "COUNT = N" / "MD = ..."
// pairs. No Len/Msg fields. parseRspMonte() handles that format.
struct RspMonteFile {
    std::vector<uint8_t>              seed;
    std::vector<std::vector<uint8_t>> checkpoints;   // typically 100
};

// cSHAKE (NIST SP 800-185) vectors carry extra parameters that plain SHAKE
// .rsp files don't: the function-name string N, the customization string S,
// and an explicit per-vector output length. Field layout per record:
//   N         = <ascii>   -- function-name string (may be empty)
//   S         = <ascii>   -- customization string (may be empty)
//   MsgLen    = <int>     -- message length in BITS
//   Msg       = <hex>     -- message bytes in hex
//   OutputLen = <int>     -- requested squeeze length in BITS
//   Output    = <hex>     -- expected output of OutputLen bits
// A record ends when Output is seen.
struct CShakeRspVector {
    int                   index = 0;
    std::string           N;
    std::string           S;
    int                   msg_len_bits = 0;
    std::vector<uint8_t>  msg;             // empty if msg_len_bits == 0
    int                   output_len_bits = 0;
    std::vector<uint8_t>  output;
};

struct RspParseError : public std::exception {
    std::string msg;
    explicit RspParseError(std::string m) : msg(std::move(m)) {}
    const char* what() const noexcept override { return msg.c_str(); }
};

// Parse a Len/Msg/MD-style .rsp (ShortMsg, LongMsg). Throws on malformed
// input or non-byte-aligned Len.
std::vector<RspVector> parseRsp(const std::string& path);

// Parse a Monte-Carlo-style .rsp (Seed + many COUNT/MD pairs). Throws on
// malformed input.
RspMonteFile parseRspMonte(const std::string& path);

// Parse a cSHAKE-style .rsp (N/S/MsgLen/Msg/OutputLen/Output records). Throws
// on malformed input or non-byte-aligned MsgLen/OutputLen.
std::vector<CShakeRspVector> parseRspCShake(const std::string& path);

// Helper exposed for unit-style use.
std::vector<uint8_t> hexToBytes(const std::string& hex);

}  // namespace sharmony
