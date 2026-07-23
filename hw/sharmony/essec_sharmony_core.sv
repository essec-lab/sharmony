///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

module essec_sharmony_core
import essec_sharmony_pkg::*;
#(
    parameter bit REG_IO     = essec_sharmony_pkg::REG_IO_DEFAULT,
    parameter int ADDER_IMPL = essec_sharmony_pkg::ADDER_IMPL_DEFAULT
)(
    input  logic                     f_clk,
    input  logic                     resetn,

    // control/config signals
    input  logic                     start,
    input  logic                     zeroize,
    input  mode_e                    mode,

    // load/save control
    input  logic                     state_load,
    input  logic                     state_save,
    input  logic                     state_cache,

    // padded message inputs
    input  logic [63:0]              blk_data,
    input  logic                     blk_write,
    input  logic                     blk_final,
    input  logic                     blk_complete,

    // SHA constant ROM request
    output logic                     rom_req,
    output logic [7:0]               rom_addr,
    input  logic [63:0]              rom_rdata,

    output logic [63:0]              output_data,
    output logic                     output_valid,
    input  logic                     output_ready,

    output logic                     stream_ready,

    // status
    output logic                     core_idle,
    output logic                     core_idle_next
);

    //---------------------------------------------------------------------------------
    //  FSM state & control strobes
    //---------------------------------------------------------------------------------
    core_fsm_e core_fsm_d;
    core_fsm_e core_fsm_q /* verilator public_flat_rd */;

    logic core_round_last;
    logic core_round_last_m1;
    logic core_round_last_m2;
    logic core_round_last_m3;
    logic digest_update_phase;
    logic digest_final_phase;
    logic digest_update, zero_active;
    logic load_iv, load_digest;
    logic blk_final_q;

    //---------------------------------------------------------------------------------
    //  Mode decode & per-mode configuration
    //---------------------------------------------------------------------------------
    logic [6:0] core_rounds_total;
    logic [7:0] const_index;

    logic mode_is_sha2;
    logic mode_is_sha2_64;
    logic mode_is_sha3;
    logic mode_is_sha3_xof;

    core_cfg_t cfg;
    always_comb begin
        unique case (mode)
            HASH_SHA2_224, HASH_SHA2_256, HASH_SHA2_384, HASH_SHA2_512,
            HASH_SHA2_512_224, HASH_SHA2_512_256,
            HASH_SHA3_224, HASH_SHA3_256, HASH_SHA3_384, HASH_SHA3_512,
            XOF_SHAKE128, XOF_SHAKE256,
            XOF_CSHAKE128, XOF_CSHAKE256: cfg = CORE_CFG_LUT[mode];
            default:                      cfg = CORE_CFG_LUT[XOF_SHAKE256];
        endcase
    end

    logic is_sha2_64_q;
    always_ff @(posedge f_clk)
        if (!resetn) is_sha2_64_q <= 1'b0;
        else         is_sha2_64_q <= cfg.is_sha2_64;

    logic mode_is_sha2_dp_q;
    always_ff @(posedge f_clk)
        if (!resetn) mode_is_sha2_dp_q <= 1'b0;
        else         mode_is_sha2_dp_q <= cfg.is_sha2;

    assign core_rounds_total = cfg.core_rounds_total;
    assign const_index       = cfg.const_index;

    assign mode_is_sha2      = cfg.is_sha2;
    assign mode_is_sha2_64   = is_sha2_64_q;

    assign mode_is_sha3      = cfg.is_sha3;
    assign mode_is_sha3_xof  = cfg.is_sha3_xof;

    //---------------------------------------------------------------------------------
    //  Inter-stage handshakes & stream ready
    //---------------------------------------------------------------------------------
    logic out_accept;
    logic u_ready;
    logic out_reg_ready;
    logic output_advance;
    logic core_stream_ready;

    assign stream_ready = core_stream_ready;

    //---------------------------------------------------------------------------------
    //  Mid-state save/load & on-chip cache control
    //---------------------------------------------------------------------------------
    logic load_state, state_load_we;

    assign load_state    = (core_fsm_q == CORE_INIT) && state_load && !state_cache && !zeroize;
    assign state_load_we = blk_write && load_state;

    logic load_state_sha3, sha3_state_load_we;

    assign load_state_sha3    = (core_fsm_q == CORE_SHA3_INIT) && state_load && !state_cache;
    assign sha3_state_load_we = blk_write && load_state_sha3;

    logic cache_save, cache_resume, cache_rotate;

    assign cache_save   = state_cache && state_save;
    assign cache_resume = state_cache && state_load;

    assign cache_rotate = cache_resume && !zeroize &&
                          ((core_fsm_q == CORE_OUTPUT_HASH) ||
                           (core_fsm_q == CORE_ROUNDS && core_round_last && blk_final_q));

    logic sha3_state_shift;
    assign sha3_state_shift = sha3_state_load_we || (state_save && mode_is_sha3 && out_accept);

    //---------------------------------------------------------------------------------
    //  Round & word counters
    //---------------------------------------------------------------------------------
    logic [1:0] word_idx_q;
    logic word_idx_clr, word_idx_en;

    logic [6:0] round_ctr_q;
    logic round_ctr_clr, round_ctr_en;
    logic round_ctr_update;
    logic [6:0] round_ctr_next;
    logic [6:0] round_ctr_q_q;

    assign round_ctr_update = round_ctr_clr | round_ctr_en;
    assign round_ctr_next   = round_ctr_clr ? 7'd0 : round_ctr_q + 7'd1;

    always_ff @(posedge f_clk) begin
        if (!resetn)
            round_ctr_q <= 7'd0;
        else if (round_ctr_update)
            round_ctr_q <= round_ctr_next;
    end

    //---------------------------------------------------------------------------------
    //  Hash state registers
    //---------------------------------------------------------------------------------
    logic [63:0] R_q [0:24] /* verilator public_flat_rd */;
    logic [63:0] R_d [0:24];

    logic [63:0] H_q [0:7] /* verilator public_flat_rd */;
    logic [63:0] H_d [0:7];

    logic [63:0] a_d, b_d, c_d, d_d, e_d, f_d, g_d, h_d;

    logic a_h_we, H_we;

    //---------------------------------------------------------------------------------
    //  SHA-2 round datapath
    //---------------------------------------------------------------------------------
    logic [63:0] iv_init1;
    logic [63:0] iv_init2;

    logic [63:0] d0_sha2_256, d1_sha2_256;
    logic [63:0] d0_sha2_512, d1_sha2_512;

    logic [63:0] sel_d0, sel_d1;

    logic [63:0] Wt15_d, W_t_d;

    logic [63:0] bsig0_256, bsig1_256;
    logic [63:0] bsig0_512, bsig1_512;

    logic [31:0] bsig0_256_hi, bsig0_256_lo;
    logic [31:0] bsig1_256_hi, bsig1_256_lo;

    (* keep = "true" *) logic [63:0] sigma0;
    (* keep = "true" *) logic [63:0] sigma1;

    logic [63:0] ch, maj, t2;
    logic [63:0] d_plus_t1, h_plus_sigma1;

    logic [63:0] wt0_plus_d0;
    logic [63:0] wt9_plus_d1;

    logic [63:0] t1_plus_t2;
    logic [63:0] H3_plus_A, H7_plus_E;

    logic [63:0] round_lane [0:24];
    logic [63:0] Wt_absorb_d;

    assign Wt15_d = (round_ctr_q < 17) ? blk_data : W_t_d;

    //---------------------------------------------------------------------------------
    //  Streaming absorb & stall control
    //---------------------------------------------------------------------------------
    logic sha3_absorb_we;

    logic sha2_stream_need_word;
    logic sha2_stream_stall;
    logic sha2_out_stall;
    logic sha2_core_advance;

    assign sha3_absorb_we = blk_write && core_fsm_q == CORE_ABSORB;

    logic [63:0] sha3_insert_data;
    assign sha3_insert_data = sha3_absorb_we ? Wt_absorb_d : R_q[0];

    assign sha2_stream_need_word =
        mode_is_sha2 &&
        ((((core_fsm_q == CORE_INIT) || (core_fsm_q == CORE_NEXT)) &&
          (word_idx_q == 2'd3)) ||
         ((core_fsm_q == CORE_ROUNDS) && (round_ctr_q < 7'd17)));

    assign sha2_stream_stall = sha2_stream_need_word && !blk_write;

    logic ehalf_emit;

    assign sha2_out_stall    = ehalf_emit && !out_reg_ready;
    assign sha2_core_advance = !(sha2_stream_stall || sha2_out_stall);

    assign rom_req = sha2_core_advance;   // == !(sha2_stream_stall || sha2_out_stall)

    logic [23:0] cfg_sha3_shift_mask;
    logic [4:0] cfg_sha3_insert_idx;
    logic [23:0] sha3_shift_mask;

    always_comb begin
        unique case (mode)
            HASH_SHA3_512: begin
                cfg_sha3_shift_mask = 24'h0000ff; // lanes 0..7
                cfg_sha3_insert_idx = 5'd8;
            end

            HASH_SHA3_384: begin
                cfg_sha3_shift_mask = 24'h000fff; // lanes 0..11
                cfg_sha3_insert_idx = 5'd12;
            end

            HASH_SHA3_256,
            XOF_SHAKE256,
            XOF_CSHAKE256: begin
                cfg_sha3_shift_mask = 24'h00ffff; // lanes 0..15
                cfg_sha3_insert_idx = 5'd16;
            end

            HASH_SHA3_224: begin
                cfg_sha3_shift_mask = 24'h01ffff; // lanes 0..16
                cfg_sha3_insert_idx = 5'd17;
            end

            default: begin // XOF_SHAKE128, XOF_CSHAKE128
                cfg_sha3_shift_mask = 24'h0fffff; // lanes 0..19
                cfg_sha3_insert_idx = 5'd20;
            end
        endcase

        // Undefined encodings (4'hE, 4'hF) behave as SHAKE256, matching the
        // cfg LUT defaults.
        if (&mode[3:1]) begin
            cfg_sha3_shift_mask = 24'h00ffff; // lanes 0..15
            cfg_sha3_insert_idx = 5'd16;
        end
    end

    assign sha3_shift_mask = sha3_state_shift ? 24'hffffff : cfg_sha3_shift_mask;

    always_comb begin : unified_registers_d
        R_d = R_q;

        // Shared shift (lanes 0-14) + non-critical working-var write. Both the
        // scrub/SHA-3-init branch and the SHA-2-advance branch do this identically,
        // so it is hoisted once. Lanes 19 (e) and 23 (a) are NOT merged here: they
        // sit on the critical E->A round path (e_d/a_d = adder outputs), and are
        // written per-branch below on a narrower select to keep that path short.
        if ((zeroize || (core_fsm_q == CORE_SHA3_INIT && !state_load)) ||
            ((load_iv || mode_is_sha2_dp_q) && sha2_core_advance)) begin
            for (int i = 0; i < 15; i = i + 1) begin
                R_d[i] = R_q[i+1];
            end
            if (a_h_we) begin
                R_d[16] = h_d;
                R_d[17] = g_d;
                R_d[18] = f_d;
                R_d[20] = d_d;
                R_d[21] = c_d;
                R_d[22] = b_d;
            end
        end

        // Per-mode overrides / SHA-3 paths (priority preserved from the original
        // nested if/else). e/a (19/23) written here on the fast per-branch select.
        if (zeroize || (core_fsm_q == CORE_SHA3_INIT && !state_load)) begin
            // SHA-3 init scrub / zeroize: zero the lanes the shift does not cover.
            R_d[3]  = 64'b0;
            R_d[8]  = 64'b0;
            R_d[12] = 64'b0;
            R_d[15] = 64'b0;
            R_d[24] = 64'b0;

            if (a_h_we) begin
                R_d[19] = e_d;
                R_d[23] = a_d;
            end

        end else if (load_iv || mode_is_sha2_dp_q) begin
            if (sha2_core_advance) begin
                R_d[15] = Wt15_d;

                if (a_h_we) begin
                    R_d[19] = e_d;
                    R_d[23] = a_d;
                end
            end

        end else begin
            if (core_fsm_q == CORE_ROUNDS) begin
                for (int i = 0; i < 25; i = i + 1) begin
                    R_d[i] = round_lane[i];
                end
            end
            else if (sha3_state_shift || sha3_absorb_we || out_accept) begin
                for (int i = 0; i < 24; i = i + 1) begin
                    if (sha3_shift_mask[i]) begin
                        R_d[i] = R_q[i+1];
                    end
                end

                if (sha3_state_shift) begin
                    R_d[24] = load_state_sha3 ? byte_swap64(blk_data) : R_q[0];
                end else begin
                    R_d[cfg_sha3_insert_idx] = sha3_insert_data;
                end
            end
        end
    end

    logic R_work_update;
    assign R_work_update =
        zeroize ||
        (core_fsm_q == CORE_SHA3_INIT) ||
        (mode_is_sha2  && sha2_core_advance) ||
        (!mode_is_sha2 && ((core_fsm_q == CORE_ROUNDS) || sha3_absorb_we || out_accept));

    always_ff @(posedge f_clk) begin : unified_registers
        if (!resetn) begin
            R_q <= '{default: '0};
        end else begin
            for (int i = 0; i < 16; i++) R_q[i] <= R_d[i];
            R_q[24] <= R_d[24];
            if (R_work_update)
                for (int i = 16; i < 24; i++) R_q[i] <= R_d[i];
        end
    end

    assign Wt_absorb_d = R_q[0] ^ byte_swap64(blk_data);

    assign iv_init2 = SHA2_IV[{mode[2:0], 1'b1, word_idx_q}];
    assign iv_init1 = SHA2_IV[{mode[2:0], 1'b0, word_idx_q}];

    logic word_idx_update;
    logic [1:0] word_idx_next;

    assign word_idx_update = word_idx_clr | word_idx_en;
    assign word_idx_next   = word_idx_clr ? 2'd0 : word_idx_q + 2'd1;

    always_ff @(posedge f_clk) begin
        if (!resetn)
            word_idx_q <= 2'd0;
        else if (word_idx_update)
            word_idx_q <= word_idx_next;
    end


    logic [63:0] ae_a_src;
    logic [63:0] ae_e_src;

    always_comb begin : ae_src_d
        unique case (1'b1)
            zero_active: begin
                ae_a_src = 64'b0;
                ae_e_src = 64'b0;
            end

            load_iv: begin
                ae_a_src = iv_init2;
                ae_e_src = iv_init1;
            end

            load_digest: begin
                ae_a_src = H_q[3];
                ae_e_src = H_q[7];
            end

            cache_rotate: begin
                ae_a_src = R_q[20];
                ae_e_src = R_q[16];
            end

            default: begin
                ae_a_src = t1_plus_t2;
                ae_e_src = d_plus_t1;
            end
        endcase
    end

    always_comb begin : state_logic
        a_d = ae_a_src;
        b_d = R_q[23];
        c_d = R_q[22];
        d_d = R_q[21];
        e_d = ae_e_src;
        f_d = R_q[19];
        g_d = R_q[18];
        h_d = R_q[17];
    end

    always_comb begin : digest_logic
        unique case (1'b1)
            load_state: begin
                H_d[0] = blk_data;
                H_d[4] = H_q[3];
            end

            zero_active: begin
                H_d[0] = 64'd0;
                H_d[4] = 64'd0;
            end

            load_iv: begin
                H_d[0] = iv_init2;
                H_d[4] = iv_init1;
            end

            digest_update: begin
                H_d[0] = H_q[3];
                H_d[4] = H_q[7];
            end

            default: begin
                H_d[0] = H3_plus_A;
                H_d[4] = H7_plus_E;
            end
        endcase

        H_d[1] = H_q[0];
        H_d[2] = H_q[1];
        H_d[3] = H_q[2];

        H_d[5] = H_q[4];
        H_d[6] = H_q[5];
        H_d[7] = H_q[6];
    end

    logic H_update;
    assign H_update = H_we & (zeroize | mode_is_sha2);

    always_ff @(posedge f_clk) begin
        if (!resetn)
            H_q <= '{default:64'b0};
        else if (H_update)
            H_q <= H_d;
    end

    logic blk_final_update;
    logic blk_final_next;

    assign blk_final_update = start | blk_complete;
    assign blk_final_next   = start ? 1'b0 : blk_final;

    always_ff @(posedge f_clk) begin
        if (!resetn)
            blk_final_q <= 1'b0;
        else if (blk_final_update)
            blk_final_q <= blk_final_next;
    end

    assign core_idle      = (core_fsm_q == CORE_IDLE);
    assign core_idle_next = (core_fsm_d == CORE_IDLE);

    //---------------------------------------------------------------------------------
    //  Core Finite State Machine (FSM)
    //---------------------------------------------------------------------------------
    // Precomputed threshold values (constants per mode)
    logic [6:0] core_rounds_total_m1;
    logic [6:0] core_rounds_total_m2;
    logic [6:0] core_rounds_total_m3;

    assign core_rounds_total_m1 = core_rounds_total - 7'd1;
    assign core_rounds_total_m2 = core_rounds_total - 7'd2;
    assign core_rounds_total_m3 = core_rounds_total - 7'd3;

    always_comb begin : core_round_flags_d
        core_round_last    = (round_ctr_q == core_rounds_total);
        core_round_last_m1 = (round_ctr_q == core_rounds_total_m1);
        core_round_last_m2 = (round_ctr_q == core_rounds_total_m2);
        core_round_last_m3 = (round_ctr_q == core_rounds_total_m3);

        // round_ctr_q < 2  (i.e. round_ctr_q[6:1] is all zero)
        digest_update_phase = ~|round_ctr_q[6:1];

        // == (round_ctr_q > core_rounds_total - 4)
        digest_final_phase  = core_round_last    |
                              core_round_last_m1 |
                              core_round_last_m2 |
                              core_round_last_m3;
    end

    logic [4:0] output_words_last;
    logic [4:0] lanes_last_index_ext;
    logic output_xof_last_word;
    logic output_hash_last_word;

    always_comb begin : lanes_output_last_d
        lanes_last_index_ext = 5'd0;
        output_words_last    = 5'd0;

        unique case (mode)
            HASH_SHA2_224: begin
                lanes_last_index_ext = 5'd15;
                output_words_last    = 5'd3;
            end

            HASH_SHA2_256,
            HASH_SHA2_384,
            HASH_SHA2_512,
            HASH_SHA2_512_224,
            HASH_SHA2_512_256: begin
                lanes_last_index_ext = 5'd15;
                output_words_last    = 5'd3;
            end

            HASH_SHA3_224: begin
                lanes_last_index_ext = 5'd17;
                output_words_last    = 5'd3;
            end

            HASH_SHA3_256: begin
                lanes_last_index_ext = 5'd16;
                output_words_last    = 5'd3;
            end

            HASH_SHA3_384: begin
                lanes_last_index_ext = 5'd12;
                output_words_last    = 5'd5;
            end

            HASH_SHA3_512: begin
                lanes_last_index_ext = 5'd8;
                output_words_last    = 5'd7;
            end

            XOF_SHAKE128,
            XOF_CSHAKE128: begin
                lanes_last_index_ext = 5'd20;
                output_words_last    = 5'd0;
            end

            XOF_SHAKE256,
            XOF_CSHAKE256: begin
                lanes_last_index_ext = 5'd16;
                output_words_last    = 5'd0;
            end

            default: begin
                lanes_last_index_ext = 5'd0;
                output_words_last    = 5'd0;
            end
        endcase

        // Undefined encodings (4'hE, 4'hF) behave as SHAKE256, matching the
        // cfg LUT defaults. Placed before the state_save override so a save
        // still exports the full state, as it would for real SHAKE256.
        if (&mode[3:1]) begin
            lanes_last_index_ext = 5'd16;
            output_words_last    = 5'd0;
        end

        // SHA-3 state_save exports the full 25-lane Keccak state (untruncated).
        if (state_save && mode_is_sha3)
            output_words_last = 5'd24;
    end

    always_ff @(posedge f_clk) begin : output_last_word_q
        if (!resetn) begin
            output_xof_last_word  <= 1'b0;
            output_hash_last_word <= 1'b0;
        end else if (round_ctr_update) begin
            output_xof_last_word  <= (round_ctr_next == 7'(lanes_last_index_ext));
            output_hash_last_word <= (round_ctr_next == 7'(output_words_last));
        end
    end

    always_comb begin
        load_iv             = 1'b0;
        load_digest         = 1'b0;
        word_idx_clr        = 1'b0;
        word_idx_en         = 1'b0;

        round_ctr_clr       = 1'b0;
        round_ctr_en        = 1'b0;
        core_stream_ready   = 1'b0;

        digest_update       = 1'b0;

        zero_active         = 1'b0;

        a_h_we              = 1'b0;
        H_we                = 1'b0;

        core_fsm_d          = core_fsm_q;

        if (zeroize) begin
            core_fsm_d        = CORE_ZEROIZE;
            zero_active       = 1'b1;
            word_idx_clr      = 1'b1;
            round_ctr_clr     = 1'b1;
            core_stream_ready = 1'b0;
            digest_update     = 1'b0;
            a_h_we            = 1'b1;
            H_we              = 1'b1;
        end else begin
            unique case (core_fsm_q)
                CORE_ZEROIZE: begin
                    if (!zeroize)
                        core_fsm_d = CORE_IDLE;
                end

                CORE_IDLE: begin
                    if (start) begin
                        if (mode_is_sha2) begin
                            if (state_load && state_cache) begin
                                round_ctr_clr = 1'b1;
                                word_idx_clr  = 1'b1;
                                core_fsm_d    = CORE_NEXT;
                            end else if (state_load) begin
                                round_ctr_clr = 1'b1;
                                word_idx_clr  = 1'b1;
                                core_fsm_d    = CORE_INIT;
                            end else begin
                                load_iv       = 1'b1;
                                word_idx_en   = 1'b1;
                                a_h_we        = 1'b1;
                                H_we          = 1'b1;
                                core_fsm_d    = CORE_INIT;
                            end
                        end else if (mode_is_sha3) begin
                            core_fsm_d  = CORE_SHA3_INIT;
                        end
                    end
                end

                CORE_SHA3_INIT: begin
                    if (state_load && !state_cache) begin
                        core_stream_ready = 1'b1;
                        if (sha3_state_load_we) begin
                            if (round_ctr_q == 7'd24) begin
                                round_ctr_clr = 1'b1;
                                core_fsm_d    = CORE_ABSORB;
                            end else begin
                                round_ctr_en  = 1'b1;
                            end
                        end
                    end else begin
                        zero_active = 1'b1;
                        a_h_we      = 1'b1;
                        if (round_ctr_q == 'd4) begin
                            core_stream_ready = 1'b1;
                            round_ctr_clr = 1'b1;
                            core_fsm_d    = CORE_ABSORB;
                        end else begin
                            round_ctr_en  = 1'b1;
                        end
                    end
                end

                CORE_INIT: begin
                    if (state_load) begin
                        core_stream_ready = 1'b1;
                        if (state_load_we) begin
                            H_we = 1'b1;
                            if (round_ctr_q == 7'd7) begin
                                round_ctr_clr = 1'b1;
                                core_fsm_d    = CORE_NEXT;
                            end else begin
                                round_ctr_en  = 1'b1;
                            end
                        end
                    end else begin
                        a_h_we              = 1'b1;
                        H_we                = 1'b1;
                        load_iv             = 1'b1;
                        word_idx_en         = 1'b1;
                        if (word_idx_q   == 'd2) begin
                            core_stream_ready   = 1'b1;
                            round_ctr_en        = 1'b1;
                        end else if (word_idx_q   == 'd3) begin
                            core_fsm_d      = CORE_ROUNDS;
                            round_ctr_en    = 1'b1;
                            word_idx_clr    = 1'b1;
                        end
                    end
                end

                CORE_NEXT: begin
                    a_h_we              = 1'b1;
                    H_we                = 1'b1;
                    load_digest         = 1'b1;
                    digest_update       = 1'b1;
                    word_idx_en         = 1'b1;
                    if (word_idx_q   == 'd2) begin
                        core_stream_ready   = 1'b1;
                        round_ctr_en        = 1'b1;
                    end else if (word_idx_q == 'd3) begin
                        core_fsm_d = CORE_ROUNDS;
                        round_ctr_en        = 1'b1;
                        word_idx_clr        = 1'b1;
                    end
                end

                CORE_ABSORB: begin
                    core_stream_ready = 1'b1;
                    if (blk_complete) begin
                        core_fsm_d      = CORE_ROUNDS;
                        round_ctr_en    = 1'b1;
                    end
                end

                CORE_ROUNDS: begin
                    a_h_we            = 1'b1;
                    round_ctr_en      = 1'b1;
                    word_idx_clr      = 1'b1;
                    load_digest       = 1'b0;
                    core_stream_ready = 1'b0;
                    if (digest_update_phase) begin
                        digest_update = 1'b1;
                        H_we          = 1'b1;
                    end

                    if (digest_final_phase) begin
                        H_we = 1'b1;
                        if (cache_resume && blk_final_q) digest_update = 1'b1;
                    end

                    if (core_round_last) begin
                        round_ctr_clr = 1'b1;

                        if (blk_final_q) begin
                            core_fsm_d = cache_save ? CORE_IDLE
                                       : (mode_is_sha3_xof && !state_save)
                                       ? CORE_OUTPUT_XOF : CORE_OUTPUT_HASH;

                        end else begin
                            word_idx_en = 1'b1;
                            load_digest = 1'b1;

                            if (mode_is_sha2) begin
                                core_fsm_d = CORE_NEXT;
                            end else begin
                                core_stream_ready = 1'b1;
                                core_fsm_d = CORE_ABSORB;
                            end
                        end
                    end
                end

                CORE_OUTPUT_HASH: begin
                    core_stream_ready = 1'b0;
                    if (output_advance) begin
                        if (cache_resume) begin
                            H_we          = 1'b1;
                            digest_update = 1'b1;
                            a_h_we        = 1'b1;
                        end else if (mode_is_sha2) begin
                            H_we          = 1'b1;
                            digest_update = 1'b1;
                        end
                        if (output_hash_last_word) begin
                            core_fsm_d    = CORE_IDLE;
                            round_ctr_clr = 1'b1;
                        end else begin
                            round_ctr_en = 1'b1;
                        end
                    end
                end

                CORE_OUTPUT_XOF: begin
                    core_stream_ready = 1'b0;
                    if (!u_ready) begin
                        core_fsm_d    = CORE_IDLE;
                        round_ctr_clr = 1'b1;
                    end else if (output_xof_last_word) begin
                        round_ctr_clr = 1'b1;
                        core_fsm_d    = CORE_WAIT;
                    end else begin
                        round_ctr_en = 1'b1;
                    end
                end

                CORE_WAIT: begin
                    core_stream_ready = 1'b0;
                    round_ctr_en      = 1'b1;
                    core_fsm_d        = CORE_ROUNDS;
                end

                default: begin
                    core_fsm_d = CORE_IDLE;
                end
            endcase

            if (sha2_stream_need_word) begin
                core_stream_ready = 1'b1;
            end

            if (sha2_stream_stall || sha2_out_stall) begin
                core_fsm_d        = core_fsm_q;

                word_idx_en       = 1'b0;
                round_ctr_en      = 1'b0;
                word_idx_clr      = 1'b0;
                round_ctr_clr     = 1'b0;

                a_h_we            = 1'b0;
                H_we              = 1'b0;
                digest_update     = 1'b0;
                load_iv           = 1'b0;
                load_digest       = 1'b0;
            end
        end
    end

    always_ff @(posedge f_clk) begin
        if (!resetn)     core_fsm_q <= CORE_IDLE;
        else             core_fsm_q <= core_fsm_d;
    end


    //---------------------------------------------------------------------------------
    //  SHA-2 Wiring and Combinatorial datapath
    //---------------------------------------------------------------------------------
`ifdef THETA_ADDER_XOR
    // Theta/adder XOR sharing: the three neighbor column parities
    // C[0]/C[3]/C[4] are computed here, ahead of the sigma muxes that steer
    // them onto the adders' b inputs. theta_step overrides its C[0]/C[3]/C[4]
    // with these same nets, so each tree exists exactly once (no reliance on
    // synthesis CSE).
    logic [63:0] theta_cx0, theta_cx3, theta_cx4;
    assign theta_cx0 = R_q[0] ^ R_q[5]  ^ R_q[10] ^ R_q[15] ^ R_q[20];
    assign theta_cx3 = R_q[3] ^ R_q[8]  ^ R_q[13] ^ R_q[18] ^ R_q[23];
    assign theta_cx4 = R_q[4] ^ R_q[9]  ^ R_q[14] ^ R_q[19] ^ R_q[24];
`endif
    always_comb begin : wsched_sigma
        d0_sha2_256 = {
            sigma0_256(R_q[1][63:32]),
            sigma0_256(R_q[1][31: 0])
        };

        d1_sha2_256 = {
            sigma1_256(R_q[14][63:32]),
            sigma1_256(R_q[14][31: 0])
        };

        // SHA-512 message-schedule sigmas operate on the full 64-bit word.
        d0_sha2_512 = sigma0_512(R_q[1]);
        d1_sha2_512 = sigma1_512(R_q[14]);

        sel_d0 = mode_is_sha2_64 ? d0_sha2_512 : d0_sha2_256;
        sel_d1 = mode_is_sha2_64 ? d1_sha2_512 : d1_sha2_256;

`ifdef THETA_ADDER_XOR
        // SHA-3: steer the EXISTING neighbor parity C[x-1] so the adders'
        // carry-propagate XOR computes the per-lane theta term lane ^ C[x-1]:
        //   add_d0: a = R_q[0] (lane 0, x=0) -> pout = A[0][0] ^ C[4]
        //   add_d1: a = R_q[9] (lane 9, x=4) -> pout = A[4][1] ^ C[3]
        if (mode_is_sha3) begin
            sel_d0 = theta_cx4;
            sel_d1 = theta_cx3;
        end
`endif
    end

    assign rom_addr = const_index + {1'b0, (mode_is_sha2 ? round_ctr_q_q : round_ctr_q)};

    always_ff @(posedge f_clk) begin
        if (!resetn)               round_ctr_q_q <= 7'b0;
        else if (round_ctr_update) round_ctr_q_q <= round_ctr_q;
    end

    logic [31:0] Wt16_hi, Wt16_lo;
    logic [31:0] Wt20_hi, Wt20_lo;

    // Wt16_* = Sigma0 input 'a' (now R_q[23]); Wt20_* = Sigma1 input 'e' (now R_q[19]).
    assign Wt16_hi = R_q[23][63:32];
    assign Wt16_lo = R_q[23][31:0 ];

    assign Wt20_hi = R_q[19][63:32];
    assign Wt20_lo = R_q[19][31:0 ];

    always_comb begin // dependency-ordered: the sequence below matters
        bsig0_256_hi = {Wt16_hi[1  : 0], Wt16_hi[31 :  2]} ^ {Wt16_hi[12 : 0], Wt16_hi[31 : 13]} ^ {Wt16_hi[21 : 0], Wt16_hi[31 : 22]};
        bsig0_256_lo = {Wt16_lo[1  : 0], Wt16_lo[31 :  2]} ^ {Wt16_lo[12 : 0], Wt16_lo[31 : 13]} ^ {Wt16_lo[21 : 0], Wt16_lo[31 : 22]};

        bsig0_256 = {bsig0_256_hi, bsig0_256_lo};

        bsig1_256_hi = {Wt20_hi[5  : 0], Wt20_hi[31 :  6]} ^ {Wt20_hi[10 : 0], Wt20_hi[31 : 11]} ^ {Wt20_hi[24 : 0], Wt20_hi[31 : 25]};
        bsig1_256_lo = {Wt20_lo[5  : 0], Wt20_lo[31 :  6]} ^ {Wt20_lo[10 : 0], Wt20_lo[31 : 11]} ^ {Wt20_lo[24 : 0], Wt20_lo[31 : 25]};

        bsig1_256 = {bsig1_256_hi,bsig1_256_lo};

        // Sigma0(a)=R_q[23], Sigma1(e)=R_q[19]; maj(a,b,c)=R_q[23,22,21]; ch(e,f,g)=R_q[19,18,17].
        bsig0_512 = {R_q[23][27:0], R_q[23][63:28]} ^ {R_q[23][33:0], R_q[23][63:34]} ^ {R_q[23][38:0], R_q[23][63:39]};
        bsig1_512 = {R_q[19][13:0], R_q[19][63:14]} ^ {R_q[19][17:0], R_q[19][63:18]} ^ {R_q[19][40:0], R_q[19][63:41]};

        maj = (R_q[23] & R_q[22]) ^ (R_q[23] & R_q[21]) ^ (R_q[22] & R_q[21]);
        ch  = (R_q[19] & R_q[18]) ^ ((~R_q[19]) & R_q[17]);
    end

    always_comb begin
        if (mode_is_sha2_64) sigma0 = bsig0_512;
        else                 sigma0 = bsig0_256;
    end
    always_comb begin
        if (mode_is_sha2_64) sigma1 = bsig1_512;
        else                 sigma1 = bsig1_256;
`ifdef THETA_ADDER_XOR
        // SHA-3: a = R_q[16] (lane 16, x=1) -> pout = A[1][3] ^ C[0].
        if (mode_is_sha3) sigma1 = theta_cx0;
`endif
    end

    //---------------------------------------------------------------------------------
    //  SHA-2 Datapath Module Instantiations
    //---------------------------------------------------------------------------------
`ifdef THETA_ADDER_XOR
    // Theta taps: the adders' carry-propagate XOR (pout = a ^ b) computes the
    // per-lane theta term lane ^ C[x-1] from the neighbor parity steered in
    // through the sigma muxes (see theta_step).
    // Only three instances are tapped; the others leave pout unconnected.
    /* verilator lint_off PINMISSING */
    logic [63:0] theta_d0_pout;    // add_d0       : R_q[0]  ^ sel_d0
    logic [63:0] theta_d1_pout;    // add_d1       : R_q[9]  ^ sel_d1
    logic [63:0] theta_hs1_pout;   // add_h_sigma1 : R_q[16] ^ sigma1
`endif
    essec_sharmony_add32_32 #(.ADDER_IMPL(ADDER_IMPL)) add_d0    (.a(sel_d0),
                          .b(R_q[0]),
                          .cin(1'b0),
                          .mode(mode_is_sha2_64),
                          .sum(wt0_plus_d0)
`ifdef THETA_ADDER_XOR
                         ,.pout(theta_d0_pout)
`endif
                          );

     essec_sharmony_add32_32 #(.ADDER_IMPL(ADDER_IMPL)) add_d1   (.a(sel_d1),
                          .b(R_q[9]),
                          .cin(1'b0),
                          .mode(mode_is_sha2_64),
                          .sum(wt9_plus_d1)
`ifdef THETA_ADDER_XOR
                         ,.pout(theta_d1_pout)
`endif
                          );

     essec_sharmony_add32_32 #(.ADDER_IMPL(ADDER_IMPL)) add_Wt   (.a(wt0_plus_d0),
                          .b(wt9_plus_d1),
                          .cin(1'b0),
                          .mode(mode_is_sha2_64),
                          .sum(W_t_d));

    //---------------------------------------------------------------------------------
    //  Tree-balanced SHA-2 main adder chain
    //---------------------------------------------------------------------------------
    // Replaces the add_Wt_Kt / add_h_s1_ch / add_t1_all / add_t1_d /
    // add_t1_plus_t2 linear chain.
    //
    // 7-operand sum for a_d: h + sigma1 + ch + R_q[15] + K + sigma0 + maj
    // 5-operand sum for e_d: R_q[19] + h + sigma1 + ch + R_q[15] + K
    //
    // Level 1 (parallel): A = h+sigma1, B = ch+R_q[15], t2 = sigma0+maj
    // Level 2 (parallel): D = A+B, E = K+t2, F = R_q[19]+K
    // Level 3 (parallel): t1_plus_t2 = D+E, d_plus_t1 = D+F

    logic [63:0] adder_B;       // ch + R_q[15]
    logic [63:0] adder_D;       // (h+sigma1) + (ch+R_q[15])
    logic [63:0] adder_E;       // K + t2
    logic [63:0] adder_F;       // R_q[19] + K

    essec_sharmony_add32_32 #(.ADDER_IMPL(ADDER_IMPL)) add_h_sigma1 (.a(R_q[16]),   // h
                             .b(sigma1),
                             .cin(1'b0),
                             .mode(mode_is_sha2_64),
                             .sum(h_plus_sigma1)
`ifdef THETA_ADDER_XOR
                            ,.pout(theta_hs1_pout)
`endif
                             );

    essec_sharmony_add32_32 #(.ADDER_IMPL(ADDER_IMPL)) add_ch_W (.a(ch),
                         .b(R_q[15]),
                         .cin(1'b0),
                         .mode(mode_is_sha2_64),
                         .sum(adder_B));

    essec_sharmony_add32_32 #(.ADDER_IMPL(ADDER_IMPL)) add_t2 (.a(sigma0),
                       .b(maj),
                       .cin(1'b0),
                       .mode(mode_is_sha2_64),
                       .sum(t2));


    essec_sharmony_add32_32 #(.ADDER_IMPL(ADDER_IMPL)) add_A_B (.a(h_plus_sigma1),
                        .b(adder_B),
                        .cin(1'b0),
                        .mode(mode_is_sha2_64),
                        .sum(adder_D));

    essec_sharmony_add32_32 #(.ADDER_IMPL(ADDER_IMPL)) add_K_t2 (.a(rom_rdata),
                         .b(t2),
                         .cin(1'b0),
                         .mode(mode_is_sha2_64),
                         .sum(adder_E));

    essec_sharmony_add32_32 #(.ADDER_IMPL(ADDER_IMPL)) add_d_K (.a(R_q[20]),   // d
                          .b(rom_rdata),            // K
                          .cin(1'b0),
                          .mode(mode_is_sha2_64),
                          .sum(adder_F));

    essec_sharmony_add32_32 #(.ADDER_IMPL(ADDER_IMPL)) add_t1_plus_t2 (.a(adder_D),
                               .b(adder_E),
                               .cin(1'b0),
                               .mode(mode_is_sha2_64),
                               .sum(t1_plus_t2));

    essec_sharmony_add32_32 #(.ADDER_IMPL(ADDER_IMPL)) add_d_plus_t1 (.a(adder_D),
                              .b(adder_F),
                              .cin(1'b0),
                              .mode(mode_is_sha2_64),
                              .sum(d_plus_t1));

    essec_sharmony_add32_32 #(.ADDER_IMPL(ADDER_IMPL)) add_H3_plus_A   (.a(H_q[3]),
                                .b(R_q[23]),   // a
                                .cin(1'b0),
                                .mode(mode_is_sha2_64),
                                .sum(H3_plus_A));

    essec_sharmony_add32_32 #(.ADDER_IMPL(ADDER_IMPL)) add_H7_plus_E   (.a(H_q[7]),
                                .b(R_q[19]),   // e
                                .cin(1'b0),
                                .mode(mode_is_sha2_64),
                                .sum(H7_plus_E));
`ifdef THETA_ADDER_XOR
    /* verilator lint_on PINMISSING */
`endif

    //---------------------------------------------------------------------------------
    //  Keccak-f[1600] step mappings: theta, rho, pi, chi, iota
    //---------------------------------------------------------------------------------
    // Implemented directly from the FIPS 202 specification on the 5x5
    // lane grid (lane index = x + 5*y) read straight from / written back
    // to the working registers R_q / round_lane.
    // 5x5 lane grid A[x][y] = R_q[x + 5*y] and the per-step-mapping intermediates.
    logic [63:0] A [0:4][0:4];       // state input lanes
    logic [63:0] C [0:4];            // theta column parity  C[x]
    logic [63:0] A_theta [0:4][0:4]; // after theta          A[x][y] ^ D[x]
    logic [63:0] B [0:4][0:4];       // after rho + pi
    logic [63:0] A_prime [0:4][0:4]; // after chi + iota

    //---------------------------------------------------------------------------------
    //  theta step mappings
    //---------------------------------------------------------------------------------
    always_comb begin : theta_step
        for (int y = 0; y < 5; y++)
            for (int x = 0; x < 5; x++)
                A[x][y] = R_q[5*y + x];

        for (int x = 0; x < 5; x++)
            C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4];

`ifdef THETA_ADDER_XOR
        // All five parities stay conventional; columns 0/3/4 alias the early
        // copies that also feed the sigma muxes (one net each).
        C[0] = theta_cx0;
        C[3] = theta_cx3;
        C[4] = theta_cx4;
`endif

        // Apply theta per lane as ONE 3-input XOR -- A[x][y] ^ C[x-1] ^
        // rotl(C[x+1],1) -- so each output bit maps to a single LUT and the
        // shared C term is not materialised into its own net/logic.
        for (int y = 0; y < 5; y++)
            for (int x = 0; x < 5; x++)
                A_theta[x][y] = A[x][y] ^ C[(x + 4) % 5] ^ { C[(x + 1) % 5][62:0], C[(x + 1) % 5][63] };

`ifdef THETA_ADDER_XOR
        // The adders' propagate XOR already carries lane ^ C[x-1]; finish
        // theta for those three lanes with only the rotated C[x+1] neighbor.
        A_theta[0][0] = theta_d0_pout  ^ { C[1][62:0], C[1][63] };  // lane 0
        A_theta[4][1] = theta_d1_pout  ^ { C[0][62:0], C[0][63] };  // lane 9
        A_theta[1][3] = theta_hs1_pout ^ { C[2][62:0], C[2][63] };  // lane 16
`endif
    end

    //---------------------------------------------------------------------------------
    //  rho + pi step mappings
    //---------------------------------------------------------------------------------
    // B[y][(2x+3y) mod 5] = rotl(theta(A)[x][y], r[x][y]).  Each rotation is
    // an explicit constant bit-slice, so it is pure wiring (no barrel
    // shifter / LUTs).  Offsets r[x][y] per FIPS 202, Table 2.
    assign B[0][0] = A_theta[0][0];
    assign B[1][3] = { A_theta[0][1][27:0], A_theta[0][1][63:28] };
    assign B[2][1] = { A_theta[0][2][60:0], A_theta[0][2][63:61] };
    assign B[3][4] = { A_theta[0][3][22:0], A_theta[0][3][63:23] };
    assign B[4][2] = { A_theta[0][4][45:0], A_theta[0][4][63:46] };
    assign B[0][2] = { A_theta[1][0][62:0], A_theta[1][0][63:63] };
    assign B[1][0] = { A_theta[1][1][19:0], A_theta[1][1][63:20] };
    assign B[2][3] = { A_theta[1][2][53:0], A_theta[1][2][63:54] };
    assign B[3][1] = { A_theta[1][3][18:0], A_theta[1][3][63:19] };
    assign B[4][4] = { A_theta[1][4][61:0], A_theta[1][4][63:62] };
    assign B[0][4] = { A_theta[2][0][1: 0], A_theta[2][0][63: 2] };
    assign B[1][2] = { A_theta[2][1][57:0], A_theta[2][1][63:58] };
    assign B[2][0] = { A_theta[2][2][20:0], A_theta[2][2][63:21] };
    assign B[3][3] = { A_theta[2][3][48:0], A_theta[2][3][63:49] };
    assign B[4][1] = { A_theta[2][4][2: 0], A_theta[2][4][63: 3] };
    assign B[0][1] = { A_theta[3][0][35:0], A_theta[3][0][63:36] };
    assign B[1][4] = { A_theta[3][1][8: 0], A_theta[3][1][63: 9] };
    assign B[2][2] = { A_theta[3][2][38:0], A_theta[3][2][63:39] };
    assign B[3][0] = { A_theta[3][3][42:0], A_theta[3][3][63:43] };
    assign B[4][3] = { A_theta[3][4][7: 0], A_theta[3][4][63:8 ] };
    assign B[0][3] = { A_theta[4][0][36:0], A_theta[4][0][63:37] };
    assign B[1][1] = { A_theta[4][1][43:0], A_theta[4][1][63:44] };
    assign B[2][4] = { A_theta[4][2][24:0], A_theta[4][2][63:25] };
    assign B[3][2] = { A_theta[4][3][55:0], A_theta[4][3][63:56] };
    assign B[4][0] = { A_theta[4][4][49:0], A_theta[4][4][63:50] };

    //---------------------------------------------------------------------------------
    //  chi + iota step mappings
    //---------------------------------------------------------------------------------
    always_comb begin : chi_iota_step
        for (int y = 0; y < 5; y++)
            for (int x = 0; x < 5; x++)
                A_prime[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]);

        // iota: xor the RC into lane (0,0)
        A_prime[0][0] = A_prime[0][0] ^ rom_rdata;

        // write the permuted lanes back in working-register order
        for (int y = 0; y < 5; y++)
            for (int x = 0; x < 5; x++)
                round_lane[5*y + x] = A_prime[x][y];
    end

    //---------------------------------------------------------------------------------
    //  Digest output interfaces
    //---------------------------------------------------------------------------------
    logic [3:0] ehalf_mask;
    assign ehalf_mask = state_save ? 4'b1111 : cfg.ehalf_mask;

    // !cache_save: a cache-save keeps the chaining value on-chip, so the
    // early E-half emission must stay silent (the FSM already suppresses the
    // OUTPUT_HASH half via cache_save -> CORE_IDLE; both doors must agree).
    assign ehalf_emit = blk_final_q && mode_is_sha2 && !cache_save &&
                        (core_fsm_q == CORE_ROUNDS) &&
                        ((core_round_last    && ehalf_mask[0]) ||
                         (core_round_last_m1 && ehalf_mask[1]) ||
                         (core_round_last_m2 && ehalf_mask[2]) ||
                         (core_round_last_m3 && ehalf_mask[3]));

    logic [63:0] sha2_data_n;
    assign sha2_data_n = (core_fsm_q == CORE_OUTPUT_HASH) ? H_q[3] : H_d[4];

    logic [63:0] sha2_data_c;
    assign sha2_data_c = (core_fsm_q == CORE_OUTPUT_HASH) ? H3_plus_A : H7_plus_E;

    logic [63:0] sha2_data;
    always_comb begin
        sha2_data = cache_resume ? sha2_data_c : sha2_data_n;
        if ((mode == HASH_SHA2_512_224) && !state_save &&
            (core_fsm_q == CORE_OUTPUT_HASH) &&
            (round_ctr_q[1:0] == 2'd0)) begin
            sha2_data[31:0] = 32'b0;
        end
    end

    //---------------------------------------------------------------------------------
    //  REG_IO=1 datapath: registered u-register + skid (buffered)
    //---------------------------------------------------------------------------------
    logic out_accept_b, u_ready_b, out_reg_ready_b, output_advance_b;
    logic output_valid_b;
    logic [63:0] output_data_b /* verilator public_flat_rd */;

    logic u_valid;
    logic [63:0] u_data /* verilator public_flat_rd */;
    logic sha2_raw_valid, sha2_load, sha3_load, output_load, output_keep;
    logic [63:0] sha3_data, u_data_n;
    logic sha3_out_first, sha3_out_next;

    assign out_accept_b    = u_valid && u_ready_b;
    assign out_reg_ready_b = !u_valid || u_ready_b;

    assign sha2_raw_valid  = mode_is_sha2 &&
                             ((core_fsm_q == CORE_OUTPUT_HASH) || ehalf_emit);
    assign sha2_load       = sha2_raw_valid && out_reg_ready_b;

    // SHA-3 look-ahead output (0 latency): commit taps round_lane[0]; each accept R_q[1].
    // !cache_save: same silence rule as ehalf_emit for the (unsupported but
    // physically drivable) state_cache && state_save pin combination in SHA-3.
    assign sha3_out_first  = mode_is_sha3 && (core_fsm_q == CORE_ROUNDS) &&
                             core_round_last && blk_final_q && !cache_save;
    assign sha3_out_next   = mode_is_sha3 && u_valid && u_ready_b &&
                             (((core_fsm_q == CORE_OUTPUT_HASH) && !output_hash_last_word) ||
                              ((core_fsm_q == CORE_OUTPUT_XOF)  && !output_xof_last_word));
    assign sha3_load       = sha3_out_first || sha3_out_next;

    always_comb begin
        sha3_data = sha3_out_first ? byte_swap64(round_lane[0]) : byte_swap64(R_q[1]);
        if ((mode == HASH_SHA3_224) && !state_save && !sha3_out_first &&
            ((round_ctr_q + 7'd1) == 7'd3)) begin
            sha3_data[31:0] = 32'b0;
        end
    end

    assign output_load = sha3_load || sha2_load;
    assign output_keep = u_valid && !u_ready_b;

    always_comb begin
        u_data_n = sha2_data;
        if (sha3_load) u_data_n = sha3_data;
    end

    assign output_advance_b = mode_is_sha2 ? sha2_load : out_accept_b;

    // u-register
    always_ff @(posedge f_clk) begin
        if (!resetn) begin
            u_valid <= 1'b0;
            u_data  <= 64'b0;
        end else if (zeroize || start) begin
            u_valid <= 1'b0;
            u_data  <= 64'b0;
        end else begin
            u_valid <= output_load || output_keep;
            if (output_load) u_data <= u_data_n;
        end
    end

    // Output skid (canonical register slice; u_ready_b = skid not full).
    logic skid_full;
    logic [63:0] skid_data /* verilator public_flat_rd */;
    assign u_ready_b = !skid_full;

    always_ff @(posedge f_clk) begin
        if (!resetn) begin
            output_valid_b <= 1'b0;
            skid_full      <= 1'b0;
            output_data_b  <= 64'b0;
            skid_data      <= 64'b0;
        end else if (zeroize || start) begin
            output_valid_b <= 1'b0;
            skid_full      <= 1'b0;
            output_data_b  <= 64'b0;
            skid_data      <= 64'b0;
        end else begin
            if (!output_valid_b || output_ready) begin
                if (skid_full) begin
                    output_valid_b <= 1'b1;
                    output_data_b  <= skid_data;
                    skid_full      <= 1'b0;
                end else begin
                    output_valid_b <= u_valid;
                    output_data_b  <= u_valid ? u_data : 64'b0;  // zero the bus when not valid
                end
            end else if (u_valid && u_ready_b) begin
                skid_full <= 1'b1;
                skid_data <= u_data;
            end
        end
    end

    //---------------------------------------------------------------------------------
    //  REG_IO=0 datapath: combinational, no register stage
    //---------------------------------------------------------------------------------
    logic out_accept_c, u_ready_c, out_reg_ready_c, output_advance_c;
    logic output_valid_c;
    logic [63:0] output_data_c;

    assign output_valid_c   = (core_fsm_q == CORE_OUTPUT_HASH) ||
                              (core_fsm_q == CORE_OUTPUT_XOF ) || ehalf_emit;
    assign out_accept_c     = output_valid_c && output_ready;
    assign u_ready_c        = output_ready;
    assign out_reg_ready_c  = output_ready;
    assign output_advance_c = out_accept_c;

    always_comb begin
        // sha2_data (flat, above) carries the SHA-2 reverse-order word + 512/224 zeroing.
        // Drive zero on the bus when the output is not valid (no stale digest bits).
        output_data_c = output_valid_c ? (mode_is_sha3 ? byte_swap64(R_q[0]) : sha2_data)
                                       : 64'b0;
        if (output_valid_c && mode == HASH_SHA3_224 && !state_save && round_ctr_q == 'd3)
            output_data_c[31:0] = 32'b0;
    end

    //---------------------------------------------------------------------------------
    //  module outputs: constant REG_IO select
    //---------------------------------------------------------------------------------
    assign out_accept     = REG_IO ? out_accept_b     : out_accept_c;
    assign u_ready        = REG_IO ? u_ready_b        : u_ready_c;
    assign out_reg_ready  = REG_IO ? out_reg_ready_b  : out_reg_ready_c;
    assign output_advance = REG_IO ? output_advance_b : output_advance_c;
    assign output_valid   = REG_IO ? output_valid_b   : output_valid_c;
    assign output_data    = REG_IO ? output_data_b    : output_data_c;

endmodule
