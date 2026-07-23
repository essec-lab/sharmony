///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

//-------------------------------------------------------------------------------------
//  THETA_ADDER_XOR -- optional SHA-3 theta / SHA-2 adder XOR sharing
//-------------------------------------------------------------------------------------
// (A macro, not a parameter: it adds `pout` ports through the adder hierarchy.)
// When defined, the theta lane terms lane ^ C[x-1] for lanes 0/9/16 are taken
// from the carry-propagate XOR of the idle SHA-2 adders add_d0 / add_d1 /
// add_h_sigma1; in SHA-3 mode the sigma muxes steer the existing parity
// C[x-1] onto their b inputs.
// `define THETA_ADDER_XOR

package essec_sharmony_pkg;

    //---------------------------------------------------------------------------------
    //  I/O register-stage select
    //---------------------------------------------------------------------------------
    //   REG_IO = 1'b1 : register all inputs and outputs (zero-combinational I/O
    //                   boundary); buffered control plane. DEFAULT.
    //   REG_IO = 1'b0 : combinational I/O (no boundary registers); lower latency
    //                   and fewer FFs, but the payload drives the long pad/core
    //                   path directly.
    // The *_idle_next look-ahead ports stay present in both configs; when
    // REG_IO = 0 they are tied off as unused in essec_sharmony_top.
    localparam bit REG_IO_DEFAULT = 1'b1;

    //---------------------------------------------------------------------------------
    //  Round-constants ROM implementation select (essec_sharmony_rom)
    //---------------------------------------------------------------------------------
    //   ROM_USE_BRAM = 1'b1 : block RAM   (rom_style="block",       1x RAMB36)
    //                = 1'b0 : distributed (rom_style="distributed", LUTRAM, no BRAM)
    // Both are functionally identical (registered-read ROM of the SHA-2/SHA-3
    // round constants); they trade one block RAM against distributed-RAM LUTs.
    localparam bit ROM_USE_BRAM_DEFAULT = 1'b1;

    //---------------------------------------------------------------------------------
    //  Adder implementation select (essec_sharmony_add32_32 dual-mode adder)
    //---------------------------------------------------------------------------------
    //   ADDER_GENERIC    : portable behavioral '+' (any FPGA family / ASIC; the
    //                      synthesis tool infers whatever carry resource exists).
    //   ADDER_CARRY4     : explicit Xilinx 7-series CARRY4 + MUXCY carry chain.
    //   ADDER_CARRY8     : explicit UltraScale/UltraScale+ CARRY8 chain.
    //                      NOTE: not a 7-series primitive.
    // Default = ADDER_CARRY4 (matches the current xc7a200t flow exactly).
    localparam int ADDER_GENERIC    = 0;
    localparam int ADDER_CARRY4     = 1;
    localparam int ADDER_CARRY8     = 2;
    localparam int ADDER_IMPL_DEFAULT = ADDER_CARRY4;

    // Zeroize hold-window index: total active zeroize window = ZEROIZE_IDX+1 cycles.
    localparam logic [2:0] ZEROIZE_IDX = 3'd4;

    typedef enum logic [3:0] {
        PAD_IDLE       = 4'd0,
        PAD_WAIT_CORE  = 4'd1,
        STREAM         = 4'd2,
        PAD_ZEROS      = 4'd3,
        PAD80_HI_ONLY  = 4'd4,
        PAD80_LO_ONLY  = 4'd5,
        PAD80_BOTH     = 4'd9,
        LEN_FIELD      = 4'd6,
        PAD_NEWBLOCK   = 4'd7,
        PAD_ZEROIZE    = 4'd8,
        PAD_STATE_LOAD = 4'd10   // state_load: forward N loaded-midstate beats raw
    } pad_fsm_e;

    typedef enum logic [3:0] {
        CORE_IDLE        = 4'd0,
        CORE_INIT        = 4'd1,
        CORE_ROUNDS      = 4'd2,
        CORE_NEXT        = 4'd3,
        CORE_WAIT        = 4'd4,
        CORE_ZEROIZE     = 4'd5,
        CORE_ABSORB      = 4'd6,
        CORE_OUTPUT_HASH = 4'd7,
        CORE_SHA3_INIT   = 4'd8,
        CORE_OUTPUT_XOF  = 4'd9
    } core_fsm_e;

    typedef enum logic [3:0] {
        HASH_SHA2_224      = 4'h0,
        HASH_SHA2_256      = 4'h1,
        HASH_SHA2_384      = 4'h2,
        HASH_SHA2_512      = 4'h3,

        HASH_SHA2_512_224  = 4'h4,
        HASH_SHA2_512_256  = 4'h5,

        HASH_SHA3_224      = 4'h6,
        HASH_SHA3_256      = 4'h7,
        HASH_SHA3_384      = 4'h8,
        HASH_SHA3_512      = 4'h9,

        XOF_SHAKE128      = 4'hA,
        XOF_SHAKE256      = 4'hB,

        XOF_CSHAKE128     = 4'hC,
        XOF_CSHAKE256     = 4'hD
    } mode_e;

    // SHA2 IVs are stored in reverse internal state order:
    // SHA2_IV[base + 0] maps to H7, SHA2_IV[base + 7] maps to H0.
    localparam logic [63:0] SHA2_IV [0:47] = '{
        // mode[2:0] = 0  SHA2-224
        64'hbefa_4fa4_befa_4fa4, 64'h64f9_8fa7_64f9_8fa7,
        64'h6858_1511_6858_1511, 64'hffc0_0b31_ffc0_0b31,
        64'hf70e_5939_f70e_5939, 64'h3070_dd17_3070_dd17,
        64'h367c_d507_367c_d507, 64'hc105_9ed8_c105_9ed8,

        // mode[2:0] = 1  SHA2-256
        64'h5be0_cd19_5be0_cd19, 64'h1f83_d9ab_1f83_d9ab,
        64'h9b05_688c_9b05_688c, 64'h510e_527f_510e_527f,
        64'ha54f_f53a_a54f_f53a, 64'h3c6e_f372_3c6e_f372,
        64'hbb67_ae85_bb67_ae85, 64'h6a09_e667_6a09_e667,

        // mode[2:0] = 2  SHA2-384
        64'h47b5_481d_befa_4fa4, 64'hdb0c_2e0d_64f9_8fa7,
        64'h8eb4_4a87_6858_1511, 64'h6733_2667_ffc0_0b31,
        64'h152f_ecd8_f70e_5939, 64'h9159_015a_3070_dd17,
        64'h629a_292a_367c_d507, 64'hcbbb_9d5d_c105_9ed8,

        // mode[2:0] = 3  SHA2-512
        64'h5be0_cd19_137e_2179, 64'h1f83_d9ab_fb41_bd6b,
        64'h9b05_688c_2b3e_6c1f, 64'h510e_527f_ade6_82d1,
        64'ha54f_f53a_5f1d_36f1, 64'h3c6e_f372_fe94_f82b,
        64'hbb67_ae85_84ca_a73b, 64'h6a09_e667_f3bc_c908,

        // mode[2:0] = 4  SHA2-512/224
        64'h1112_e6ad_91d6_92a1, 64'h3f9d_85a8_6a1d_36c8,
        64'h77e3_6f73_04c4_8942, 64'h0f6d_2b69_7bd4_4da8,
        64'h679d_d514_582f_9fcf, 64'h1dfa_b7ae_32ff_9c82,
        64'h73e1_9966_89dc_d4d6, 64'h8c3d_37c8_1954_4da2,

        // mode[2:0] = 5  SHA2-512/256
        64'h0eb7_2ddc_81c5_2ca2, 64'h2b01_99fc_2c85_b8aa,
        64'hbe5e_1e25_5386_3992, 64'h9628_3ee2_a88e_ffe3,
        64'h9638_7719_5940_eabd, 64'h2393_b86b_6f53_b151,
        64'h9f55_5fa3_c84c_64c2, 64'h2231_2194_fc2b_f72c
    };

    typedef enum logic [7:0] {
        SHA256_INDEX = 8'd0,
        SHA512_INDEX = 8'd64,
        SHA3RC_INDEX = 8'd144
    } const_index_e;

    // Per-module config structs: each submodule's port carries ONLY the fields
    // it consumes (split from the old monolithic cfg_t -> no unused-field lint,
    // no interface creep).
    typedef struct packed {
        const_index_e const_index;
        logic [6:0] core_rounds_total;
        logic is_sha2;
        logic is_sha2_64;
        logic is_sha3;
        logic is_sha3_xof;
        logic [3:0] ehalf_mask;   // E-half emit mask: bit i = (emit E-half word i)
    } core_cfg_t;

    typedef struct packed {
        logic [7:0] domain_suffix;
        logic [4:0] lanes_last_index;
        logic is_sha2;
        logic is_sha2_32;
    } pad_cfg_t;

    localparam logic [3:0] NUM_MODES = 4'd14;

    // core cfg = {const_index, core_rounds_total, is_sha2, is_sha2_64, is_sha3, is_sha3_xof, ehalf_mask}
    // ehalf_mask: # E-half digest words to emit early (256/512=4->1111, 224=3->0111,
    //             384=2->0011, 512/224 & 512/256 A-half-only=0->0000; SHA-3 don't-care).
    localparam core_cfg_t CORE_CFG_LUT [NUM_MODES] = '{
        '{SHA256_INDEX, 7'd66, 1'b1, 1'b0, 1'b0, 1'b0, 4'b0111}, // SHA2-224
        '{SHA256_INDEX, 7'd66, 1'b1, 1'b0, 1'b0, 1'b0, 4'b1111}, // SHA2-256
        '{SHA512_INDEX, 7'd82, 1'b1, 1'b1, 1'b0, 1'b0, 4'b0011}, // SHA2-384
        '{SHA512_INDEX, 7'd82, 1'b1, 1'b1, 1'b0, 1'b0, 4'b1111}, // SHA2-512
        '{SHA512_INDEX, 7'd82, 1'b1, 1'b1, 1'b0, 1'b0, 4'b0000}, // SHA2-512/224
        '{SHA512_INDEX, 7'd82, 1'b1, 1'b1, 1'b0, 1'b0, 4'b0000}, // SHA2-512/256
        '{SHA3RC_INDEX, 7'd24, 1'b0, 1'b0, 1'b1, 1'b0, 4'b0000}, // SHA3-224
        '{SHA3RC_INDEX, 7'd24, 1'b0, 1'b0, 1'b1, 1'b0, 4'b0000}, // SHA3-256
        '{SHA3RC_INDEX, 7'd24, 1'b0, 1'b0, 1'b1, 1'b0, 4'b0000}, // SHA3-384
        '{SHA3RC_INDEX, 7'd24, 1'b0, 1'b0, 1'b1, 1'b0, 4'b0000}, // SHA3-512
        '{SHA3RC_INDEX, 7'd24, 1'b0, 1'b0, 1'b1, 1'b1, 4'b0000}, // SHAKE128
        '{SHA3RC_INDEX, 7'd24, 1'b0, 1'b0, 1'b1, 1'b1, 4'b0000}, // SHAKE256
        '{SHA3RC_INDEX, 7'd24, 1'b0, 1'b0, 1'b1, 1'b1, 4'b0000}, // cSHAKE128
        '{SHA3RC_INDEX, 7'd24, 1'b0, 1'b0, 1'b1, 1'b1, 4'b0000}  // cSHAKE256
    };

    // pad cfg = {domain_suffix, lanes_last_index, is_sha2, is_sha2_32}
    localparam pad_cfg_t PAD_CFG_LUT [NUM_MODES] = '{
        '{8'h80, 5'd15, 1'b1, 1'b1}, // SHA2-224
        '{8'h80, 5'd15, 1'b1, 1'b1}, // SHA2-256
        '{8'h80, 5'd15, 1'b1, 1'b0}, // SHA2-384
        '{8'h80, 5'd15, 1'b1, 1'b0}, // SHA2-512
        '{8'h80, 5'd15, 1'b1, 1'b0}, // SHA2-512/224
        '{8'h80, 5'd15, 1'b1, 1'b0}, // SHA2-512/256
        '{8'h06, 5'd17, 1'b0, 1'b0}, // SHA3-224
        '{8'h06, 5'd16, 1'b0, 1'b0}, // SHA3-256
        '{8'h06, 5'd12, 1'b0, 1'b0}, // SHA3-384
        '{8'h06, 5'd8 , 1'b0, 1'b0}, // SHA3-512
        '{8'h1F, 5'd20, 1'b0, 1'b0}, // SHAKE128
        '{8'h1F, 5'd16, 1'b0, 1'b0}, // SHAKE256
        '{8'h04, 5'd20, 1'b0, 1'b0}, // cSHAKE128  (rate = 1344 bit, domain = 0x04)
        '{8'h04, 5'd16, 1'b0, 1'b0}  // cSHAKE256  (rate = 1088 bit, domain = 0x04)
    };

    function automatic [63:0] byte_swap64(input [63:0] x);
        begin
        byte_swap64 = { x[7 : 0], x[15: 8], x[23:16], x[31:24],
                        x[39:32], x[47:40], x[55:48], x[63:56] };
        end
    endfunction

    //---------------------------------------------------------------------------------
    //  SHA-2 message-schedule sigma functions
    //---------------------------------------------------------------------------------
    // Lowercase small-sigma. The round big-Sigma functions are computed inline
    // in essec_sharmony_core (named bsig0/bsig1).
    function automatic logic [31:0] rotr32(input logic [31:0] x, input int n);
        return (x >> n) | (x << (32-n));
    endfunction

    function automatic logic [63:0] rotr64(input logic [63:0] x, input int n);
        return (x >> n) | (x << (64-n));
    endfunction

    function automatic logic [31:0] sigma0_256(input logic [31:0] x);
        return rotr32(x,7) ^ rotr32(x,18) ^ (x >> 3);
    endfunction

    function automatic logic [31:0] sigma1_256(input logic [31:0] x);
        return rotr32(x,17) ^ rotr32(x,19) ^ (x >> 10);
    endfunction

    function automatic logic [63:0] sigma0_512(input logic [63:0] x);
        return rotr64(x,1) ^ rotr64(x,8) ^ (x >> 7);
    endfunction

    function automatic logic [63:0] sigma1_512(input logic [63:0] x);
        return rotr64(x,19) ^ rotr64(x,61) ^ (x >> 6);
    endfunction

    // Padding function
    /* verilator lint_off UNUSEDSIGNAL */
    function automatic logic [63:0] apply_padding(
        input logic [63:0] data,
        input logic [2:0]  valid_bytes,
        input logic [7:0]  suffix
    );
        logic [63:0] out;
        case (valid_bytes)
            3'd0: out = {             suffix, 56'h0};
            3'd1: out = {data[63:56], suffix, 48'h0};
            3'd2: out = {data[63:48], suffix, 40'h0};
            3'd3: out = {data[63:40], suffix, 32'h0};
            3'd4: out = {data[63:32], suffix, 24'h0};
            3'd5: out = {data[63:24], suffix, 16'h0};
            3'd6: out = {data[63:16], suffix,  8'h0};
            3'd7: out = {data[63: 8], suffix};
            default: out = 64'h0;
        endcase
        return out;
    endfunction

    function automatic logic [31:0] apply_padding32(
        input logic [31:0] data,
        input logic [1:0]  valid_bytes
    );
        logic [31:0] out;
        case (valid_bytes)
            2'd0: out = 32'h8000_0000;
            2'd1: out = {data[31:24], 8'h80, 16'h0000};
            2'd2: out = {data[31:16], 8'h80,  8'h00};
            2'd3: out = {data[31: 8], 8'h80};
            default: out = 32'h0;
        endcase
        return out;
    endfunction
    /* verilator lint_on UNUSEDSIGNAL */
endpackage
