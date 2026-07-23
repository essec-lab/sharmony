///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Minimal SystemVerilog wrapper for the Verilator C++ testbench flow.
//
// Instantiates only the DUT and exposes its ports as plain logic vectors so
// that the C++ side does not need to know about essec_sharmony_pkg::mode_e.
// No SV test modules are instantiated here - the C++ testbench drives all
// pins directly.
//
// MODE encoding (from essec_sharmony_pkg::mode_e):
//   4'h0 HASH_SHA2_224     4'h6 HASH_SHA3_224     4'hC XOF_CSHAKE128
//   4'h1 HASH_SHA2_256     4'h7 HASH_SHA3_256     4'hD XOF_CSHAKE256
//   4'h2 HASH_SHA2_384     4'h8 HASH_SHA3_384
//   4'h3 HASH_SHA2_512     4'h9 HASH_SHA3_512
//   4'h4 HASH_SHA2_512_224 4'hA XOF_SHAKE128
//   4'h5 HASH_SHA2_512_256 4'hB XOF_SHAKE256
//
///////////////////////////////////////////////////////////////////////////////////////

module sharmony_verilator_wrapper
  import essec_sharmony_pkg::*;
(
  input  logic        f_clk,
  input  logic        resetn,

  input  logic        start,
  input  logic        zeroize,
  input  logic [3:0]  mode,           // mode_e
  input  logic        state_load,     // midstate caching: load state vs IV/zero
  input  logic        state_save,     // midstate caching: export state vs digest
  input  logic        state_cache,    // midstate caching: internal 1-slot cache (SHA-2)

  input  logic [63:0] input_data,
  input  logic        input_valid,
  input  logic [5:0]  input_bytes,
  input  logic [1:0]  input_final,
  output logic        input_ready,

  output logic [63:0] output_data,
  output logic        output_valid,
  input  logic        output_ready,
  output logic        busy
);

  // Cast the raw 4-bit mode input to the strongly-typed enum the DUT expects.
  mode_e mode_typed;
  assign mode_typed = mode_e'(mode);

  essec_sharmony_top dut (
    .f_clk        (f_clk),
    .resetn      (resetn),
    .start        (start),
    .zeroize      (zeroize),
    .mode         (mode_typed),
    .state_load   (state_load),
    .state_save   (state_save),
    .state_cache  (state_cache),
    .input_data   (input_data),
    .input_valid  (input_valid),
    .input_bytes  (input_bytes),
    .input_final  (input_final),
    .input_ready  (input_ready),
    .output_data  (output_data),
    .output_valid (output_valid),
    .busy        (busy),
    .output_ready    (output_ready)
  );

endmodule
