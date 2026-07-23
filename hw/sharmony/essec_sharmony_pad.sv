///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

module essec_sharmony_pad
import essec_sharmony_pkg::*;
#(
    parameter bit REG_IO = essec_sharmony_pkg::REG_IO_DEFAULT
)(
    input  logic        f_clk,

    // control/config signals
    input  logic        resetn,
    input  logic        start,
    input  logic        zeroize,
    input  mode_e       mode,

    // load/save control
    input  logic        state_load,
    input  logic        state_save,
    input  logic        state_cache,

    // message stream inputs
    input  logic [63:0] input_data,
    input  logic        input_valid,
    input  logic [5:0]  input_bytes,
    input  logic [1:0]  input_final,
    output logic        input_ready,

    // padder --> core
    output logic [63:0] blk_data,
    output logic        blk_write,
    output logic        blk_final,
    output logic        blk_complete,

    // handshakes
    input  logic        core_stream_ready,

    // status
    output logic        pad_idle,
    output logic        pad_idle_next
);

    //---------------------------------------------------------------------------------
    //  FSM state & mode decode
    //---------------------------------------------------------------------------------
    pad_fsm_e pad_fsm_d, pad_fsm_q;

    logic mode_is_sha2;
    logic mode_is_sha2_32;

    pad_cfg_t cfg;
    always_comb begin
        unique case (mode)
            HASH_SHA2_224, HASH_SHA2_256, HASH_SHA2_384, HASH_SHA2_512,
            HASH_SHA2_512_224, HASH_SHA2_512_256,
            HASH_SHA3_224, HASH_SHA3_256, HASH_SHA3_384, HASH_SHA3_512,
            XOF_SHAKE128, XOF_SHAKE256,
            XOF_CSHAKE128, XOF_CSHAKE256: cfg = PAD_CFG_LUT[mode];
            default:                      cfg = PAD_CFG_LUT[XOF_SHAKE256];
        endcase
    end

    assign mode_is_sha2      = cfg.is_sha2;
    assign mode_is_sha2_32   = cfg.is_sha2_32;

    logic [7:0] domain_suffix;
    logic [4:0] lanes_last_index;
    logic [4:0] mode_last_index;

    assign lanes_last_index = cfg.lanes_last_index;
    assign domain_suffix    = cfg.domain_suffix;

    assign mode_last_index = lanes_last_index - 5'd1 - {4'b0, mode_is_sha2};

    // state_load: number of raw midstate beats to forward before the message.
    // SHA-2 = 8 (H_q[0:7]); SHA-3 = 25 (R_q[0:24] Keccak state).
    logic [4:0] state_beats_last;
    assign state_beats_last = mode_is_sha2 ? 5'd7 : 5'd24;

    //---------------------------------------------------------------------------------
    //  Message length counters
    //---------------------------------------------------------------------------------
    logic [4:0] word_cnt_d, word_cnt_q; // 5-bit registers up-to 32 words include SHA-3

    logic [63:0] byte_len_hi_d, byte_len_hi_q;
    logic [63:0] byte_len_lo_d, byte_len_lo_q;
    logic [63:0] bits_len_hi_d, bits_len_lo_d;

    // Length-counter helpers -- single shared lo adder with carry-out into the hi adder.
    logic [64:0] byte_len_lo_sum;
    logic [2:0] byte_len_hi_inc3;
    logic [5:0] byte_len_lo_inc6;

    //---------------------------------------------------------------------------------
    //  Input capture & finalization flags
    //---------------------------------------------------------------------------------
    logic [1:0] is_final_d, is_final_q;
    logic all_lanes_final;

    logic [63:0] in_data_q /* verilator public_flat_rd */;
    logic [5:0] in_bytes_q /* verilator public_flat_rd */;
    logic [1:0] in_final_q;
    logic accept_msg;

generate
if (REG_IO) begin : g_in_buf
    // Producer holds {data,bytes,final} stable while valid until input_ready (AXI).
    logic stream_active, stream_next;
    logic in_valid_q,    in_valid_d;
    logic clear_in, in_slice_ready, in_load;
    logic input_ready_n, input_ready_r;

    assign clear_in       = zeroize || start;
    assign stream_active  = ((pad_fsm_q == STREAM) || (pad_fsm_q == PAD_STATE_LOAD)) && !zeroize;
    assign stream_next    = ((pad_fsm_d == STREAM) || (pad_fsm_d == PAD_STATE_LOAD)) && !zeroize;
    assign accept_msg     = in_valid_q && stream_active;

    // Current-cycle ready of the internal 1-deep buffer.
    assign in_slice_ready = !in_valid_q || accept_msg;
    assign in_load        = in_slice_ready && input_valid;

    // True next occupancy: clear, update when slice ready, else hold full/empty.
    always_comb begin
        in_valid_d = in_valid_q;
        if (clear_in)            in_valid_d = 1'b0;
        else if (in_slice_ready) in_valid_d = input_valid;
    end

    logic [1:0] final_acked_q, final_acked_d;
    logic all_final_acked;
    assign final_acked_d = clear_in                        ? 2'b00
                         : (input_ready_r && input_valid)  ? (final_acked_q | input_final)
                                                           : final_acked_q;
    assign all_final_acked = mode_is_sha2_32 ? (final_acked_d == 2'b11)
                                             : (final_acked_d != 2'b00);
    assign input_ready_n = (!in_valid_d || stream_next)
                         && !pad_idle_next && !zeroize && !all_final_acked;
    always_ff @(posedge f_clk) begin
        if (!resetn)  final_acked_q <= 2'b00;
        else          final_acked_q <= final_acked_d;
    end

    assign input_ready = input_ready_r;

    always_ff @(posedge f_clk) begin
        if (!resetn) input_ready_r <= 1'b0;   // not ready at reset (no active transaction)
        else         input_ready_r <= input_ready_n;
    end
    always_ff @(posedge f_clk) begin
        if (!resetn) in_valid_q <= 1'b0;
        else         in_valid_q <= in_valid_d;
    end
    always_ff @(posedge f_clk) begin
        if (!resetn || zeroize) begin
            in_data_q  <= '0;
            in_bytes_q <= '0;
            in_final_q <= '0;
        end else if (in_load) begin
            in_data_q  <= input_data;
            in_bytes_q <= input_bytes;
            in_final_q <= input_final;
        end
    end
end else begin : g_in_comb
    // Combinational passthrough (no input buffer): FSM consumes input_* directly.
    assign in_data_q   = input_data;
    assign in_bytes_q  = input_bytes;
    assign in_final_q  = input_final;
    assign input_ready = (pad_fsm_q == STREAM) || (pad_fsm_q == PAD_STATE_LOAD);
    assign accept_msg  = input_valid && input_ready;
end
endgenerate

    assign bits_len_hi_d = byte_len_hi_q << 3;
    assign bits_len_lo_d = byte_len_lo_q << 3;

    // Precomputed length-field words shared between word_cnt=14 and word_cnt=15 cases.
    logic [63:0] sha2_len_hi_word;
    logic [63:0] sha2_len_lo_word;

    assign sha2_len_hi_word = mode_is_sha2_32
                            ? {bits_len_hi_d[63:32], bits_len_lo_d[63:32]}
                            : bits_len_hi_d;
    assign sha2_len_lo_word = mode_is_sha2_32
                            ? {bits_len_hi_d[31:0], bits_len_lo_d[31:0]}
                            : bits_len_lo_d;

    assign all_lanes_final = mode_is_sha2_32 ? (is_final_q == 2'b11) : (is_final_q != 2'b00);

    function automatic pad_fsm_e next_pad_state_after_write(
        input logic [4:0] wc,
        input logic [4:0] mode_last
    );
        if (wc == mode_last) begin
            return LEN_FIELD;
        end else begin
            return PAD_ZEROS;
        end
    endfunction

    //---------------------------------------------------------------------------------
    //  Message input length counter
    //---------------------------------------------------------------------------------
    assign byte_len_hi_inc3 = mode_is_sha2_32 ? in_bytes_q[5:3] : 3'd0;
    assign byte_len_lo_inc6 = mode_is_sha2_32 ? {3'd0, in_bytes_q[2:0]} : in_bytes_q;

    assign byte_len_lo_sum  = {1'b0, byte_len_lo_q} + 65'(byte_len_lo_inc6);

    always_comb begin : byte_len_logic
        byte_len_hi_d = byte_len_hi_q;
        byte_len_lo_d = byte_len_lo_q;

        if (start) begin
            if (state_load && state_cache) begin
                byte_len_hi_d = mode_is_sha2_32 ? 64'd64 : 64'd0;
                byte_len_lo_d = mode_is_sha2_32 ? 64'd64 : 64'd128;
            end else begin
                byte_len_hi_d = 64'd0;
                byte_len_lo_d = 64'd0;
            end

        end else if (pad_fsm_q == PAD_STATE_LOAD) begin
            if (mode_is_sha2 && accept_msg && (word_cnt_q == state_beats_last)) begin
                byte_len_hi_d = mode_is_sha2_32 ? 64'd64 : 64'd0;
                byte_len_lo_d = mode_is_sha2_32 ? 64'd64 : 64'd128;
            end

        end else if (accept_msg) begin
            byte_len_lo_d = byte_len_lo_sum[63:0];
            byte_len_hi_d = byte_len_hi_q
                          + 64'(byte_len_hi_inc3)
                          + 64'(byte_len_lo_sum[64]);
        end
    end

    always_comb begin : is_final_logic
        is_final_d = is_final_q;

        if (start) begin
            is_final_d = 2'b00;
        end else if ((pad_fsm_q != PAD_STATE_LOAD) && accept_msg) begin
            is_final_d = is_final_q | in_final_q;
        end
    end

    logic pad_state_ce;
    assign pad_state_ce = zeroize | start | accept_msg | blk_write | (pad_fsm_q != pad_fsm_d);

    always_ff @(posedge f_clk) begin
        if (!resetn) begin
            word_cnt_q    <= '0;
            byte_len_hi_q <= '0;
            byte_len_lo_q <= '0;
            is_final_q    <= '0;
        end else if (pad_state_ce) begin
            word_cnt_q    <= word_cnt_d;
            byte_len_hi_q <= byte_len_hi_d;
            byte_len_lo_q <= byte_len_lo_d;
            is_final_q    <= is_final_d;
        end
    end

    logic pad80_hi_done_d, pad80_hi_done_q;
    logic pad80_lo_done_d, pad80_lo_done_q;

    always_ff @(posedge f_clk) begin
        if (!resetn) begin
            pad80_hi_done_q <= 1'b0;
            pad80_lo_done_q <= 1'b0;
        end else if (zeroize) begin
            pad80_hi_done_q <= 1'b0;
            pad80_lo_done_q <= 1'b0;
        end else begin
            pad80_hi_done_q <= pad80_hi_done_d;
            pad80_lo_done_q <= pad80_lo_done_d;
        end
    end

    logic state_done_d, state_done_q;
    always_ff @(posedge f_clk) begin
        if (!resetn || zeroize || start) state_done_q <= 1'b0;
        else                             state_done_q <= state_done_d;
    end

    assign pad_idle      = (pad_fsm_q == PAD_IDLE);
    assign pad_idle_next = (pad_fsm_d == PAD_IDLE);   // look-ahead for busy register

    logic [31:0] padded32_lo, padded32_hi;
    logic [2:0] bytes_hi, bytes_lo;
    logic hi_full, lo_full;

    logic [4:0] next_word_idx;

    assign next_word_idx = word_cnt_q + 5'd1;

    //---------------------------------------------------------------------------------
    //  Shared after-write padding decode
    //---------------------------------------------------------------------------------
    // Factored out of PAD80_HI/LO/BOTH; computes next word_cnt / fsm /
    // complete / final once instead of three times.
    logic pad_word_last;
    logic pad_last_sha3;

    logic [4:0] pad_next_word_cnt;
    pad_fsm_e pad_next_fsm;
    logic pad_next_complete;
    logic pad_next_final;

    assign pad_word_last = (word_cnt_q == lanes_last_index);
    assign pad_last_sha3 = pad_word_last & ~mode_is_sha2;

    //---------------------------------------------------------------------------------
    //  STREAM in_final_q / pending-padding predecode (computed once)
    //---------------------------------------------------------------------------------
    logic final_none;
    logic final_lo;
    logic final_hi;
    logic need_hi_pad32;
    logic need_lo_pad32;

    assign final_none = ~|in_final_q;
    assign final_lo   =  in_final_q[0] & ~in_final_q[1];
    assign final_hi   =  in_final_q[1] & ~in_final_q[0];

    assign need_hi_pad32 = mode_is_sha2_32 && is_final_q[1] && !pad80_hi_done_q;
    assign need_lo_pad32 = mode_is_sha2_32 && is_final_q[0] && !pad80_lo_done_q;

    //---------------------------------------------------------------------------------
    //  Padding-word generators (mode-multiplexed once; used by PAD80_HI/LO/BOTH)
    //---------------------------------------------------------------------------------
    logic [63:0] pad_hi_word;
    logic [63:0] pad_lo_word;
    logic [63:0] pad_both_word;

    assign pad_hi_word     = {domain_suffix, 56'h0};
    assign pad_lo_word     = mode_is_sha2_32 ? {32'h0, 32'h8000_0000}
                                             : {domain_suffix, 56'h0};
    assign pad_both_word   = pad_hi_word | pad_lo_word;

    always_comb begin : pad_after_write_decode_d
        pad_next_word_cnt = next_word_idx;
        pad_next_fsm      = next_pad_state_after_write(word_cnt_q, mode_last_index);
        pad_next_complete = 1'b0;
        pad_next_final    = 1'b0;

        if (pad_word_last) begin
            pad_next_word_cnt = '0;
            pad_next_complete = 1'b1;

            if (mode_is_sha2) begin
                pad_next_fsm = PAD_NEWBLOCK;
            end else begin
                pad_next_fsm   = PAD_IDLE;
                pad_next_final = 1'b1;
            end
        end
    end

    //---------------------------------------------------------------------------------
    //  Padding Finite State Machine (FSM)
    //---------------------------------------------------------------------------------
    logic [4:0] word_cnt_stream_d;
    assign word_cnt_stream_d = pad_word_last ? '0 : next_word_idx;

    always_comb begin
        blk_data          = 64'h0;
        blk_write         = 1'b0;
        blk_final         = 1'b0;
        blk_complete      = 1'b0;
        word_cnt_d        = word_cnt_q;
        pad_fsm_d         = pad_fsm_q;

        bytes_hi          = in_bytes_q[5:3];
        bytes_lo          = in_bytes_q[2:0];
        hi_full           = bytes_hi[2];   // bytes_hi<=4 by protocol, so [2] <=> ==4
        lo_full           = bytes_lo[2];

        padded32_hi       = apply_padding32(in_data_q[63:32], bytes_hi[1:0]);
        padded32_lo       = apply_padding32(in_data_q[31:0],  bytes_lo[1:0]);

        pad80_hi_done_d   = pad80_hi_done_q;
        pad80_lo_done_d   = pad80_lo_done_q;
        state_done_d      = state_done_q;

        if(zeroize) begin
            pad_fsm_d = PAD_ZEROIZE;
        end else begin
            unique case (pad_fsm_q)
                PAD_ZEROIZE: begin
                    if(!zeroize) begin
                        pad_fsm_d = PAD_IDLE;
                    end
                end

                PAD_IDLE: begin
                    if(start) begin
                        pad80_hi_done_d = 1'b0;
                        pad80_lo_done_d = 1'b0;
                        if (core_stream_ready) begin
                            pad_fsm_d = (state_load && !state_cache && !state_done_q) ? PAD_STATE_LOAD : STREAM;
                        end else begin
                            pad_fsm_d = PAD_WAIT_CORE;
                        end
                    end
                end

                PAD_STATE_LOAD: begin
                    if (accept_msg) begin
                        blk_write  = 1'b1;
                        blk_data   = in_data_q;
                        word_cnt_d = next_word_idx;
                        if (word_cnt_q == state_beats_last) begin
                            word_cnt_d   = '0;
                            state_done_d = 1'b1;
                            pad_fsm_d    = PAD_WAIT_CORE;
                        end
                    end
                end

                PAD_WAIT_CORE: begin
                    word_cnt_d  = 5'b0;
                    if (core_stream_ready) begin
                        pad_fsm_d = (state_load && !state_cache && !state_done_q) ? PAD_STATE_LOAD : STREAM;
                    end
                end

                STREAM: begin
                    if (accept_msg) begin
                        blk_write  = 1'b1;
                        word_cnt_d = word_cnt_stream_d;

                        if (pad_word_last) begin
                            blk_complete = 1'b1;
                            pad_fsm_d    = PAD_NEWBLOCK;
                        end else begin
                            pad_fsm_d    = STREAM;
                        end

                        if (state_save && (|in_final_q) && pad_word_last) begin
                            blk_data     = in_data_q;
                            blk_complete = 1'b1;
                            blk_final    = 1'b1;
                            word_cnt_d   = '0;
                            pad_fsm_d    = PAD_IDLE;
                        end else if (mode_is_sha2_32) begin
                            priority case (1'b1)
                                need_hi_pad32: begin
                                    pad80_hi_done_d = 1'b1;

                                    if (final_lo && !lo_full) begin
                                        blk_data        = {32'h8000_0000, padded32_lo};
                                        pad80_lo_done_d = 1'b1;
                                        word_cnt_d      = pad_next_word_cnt;
                                        pad_fsm_d       = pad_next_fsm;
                                        blk_complete    = pad_next_complete;
                                    end else begin
                                        blk_data = {32'h8000_0000, in_data_q[31:0]};
                                        if (in_final_q[0]) pad80_lo_done_d = 1'b0;
                                        if (!pad_word_last) begin
                                            pad_fsm_d = in_final_q[0] ? PAD80_LO_ONLY : STREAM;
                                        end
                                    end
                                end

                                // Pending low-half padding from previous beat.
                                need_lo_pad32: begin
                                    pad80_lo_done_d = 1'b1;

                                    if (final_hi && !hi_full) begin
                                        blk_data        = {padded32_hi, 32'h8000_0000};
                                        pad80_hi_done_d = 1'b1;
                                        word_cnt_d      = pad_next_word_cnt;
                                        pad_fsm_d       = pad_next_fsm;
                                        blk_complete    = pad_next_complete;
                                    end else begin
                                        blk_data = {in_data_q[63:32], 32'h8000_0000};
                                        if (in_final_q[1]) pad80_hi_done_d = 1'b0;
                                        if (!pad_word_last) begin
                                            pad_fsm_d = in_final_q[1] ? PAD80_HI_ONLY : STREAM;
                                        end
                                    end
                                end

                                // Non-final word.
                                final_none: begin
                                    blk_data = in_data_q;
                                    if (pad_word_last) pad_fsm_d = PAD_WAIT_CORE;
                                end

                                // SHA-2-32 current final beat.
                                default: begin
                                    unique case (in_final_q)
                                        2'b01: begin
                                            if (lo_full) begin
                                                blk_data        = in_data_q;
                                                pad80_lo_done_d = 1'b0;
                                                if (!pad_word_last) begin
                                                    pad_fsm_d = pad80_hi_done_q ? PAD80_LO_ONLY : STREAM;
                                                end
                                            end else begin
                                                blk_data        = {in_data_q[63:32], padded32_lo};
                                                pad80_lo_done_d = 1'b1;
                                                if (pad80_hi_done_q) begin
                                                    word_cnt_d   = pad_next_word_cnt;
                                                    pad_fsm_d    = pad_next_fsm;
                                                    blk_complete = pad_next_complete;
                                                end
                                            end
                                        end

                                        2'b10: begin
                                            if (hi_full) begin
                                                blk_data        = in_data_q;
                                                pad80_hi_done_d = 1'b0;
                                                if (!pad_word_last) begin
                                                    pad_fsm_d = pad80_lo_done_q ? PAD80_HI_ONLY : STREAM;
                                                end
                                            end else begin
                                                blk_data        = {padded32_hi, in_data_q[31:0]};
                                                pad80_hi_done_d = 1'b1;
                                                if (pad80_lo_done_q) begin
                                                    word_cnt_d   = pad_next_word_cnt;
                                                    pad_fsm_d    = pad_next_fsm;
                                                    blk_complete = pad_next_complete;
                                                end
                                            end
                                        end

                                        default: begin
                                            unique case ({hi_full, lo_full})
                                                2'b11: begin
                                                    blk_data        = in_data_q;
                                                    pad80_hi_done_d = 1'b0;
                                                    pad80_lo_done_d = 1'b0;
                                                    if (!pad_word_last) pad_fsm_d = PAD80_BOTH;
                                                end
                                                2'b10: begin
                                                    blk_data        = {in_data_q[63:32], padded32_lo};
                                                    pad80_hi_done_d = 1'b0;
                                                    pad80_lo_done_d = 1'b1;
                                                    if (!pad_word_last) pad_fsm_d = PAD80_HI_ONLY;
                                                end
                                                2'b01: begin
                                                    blk_data        = {padded32_hi, in_data_q[31:0]};
                                                    pad80_hi_done_d = 1'b1;
                                                    pad80_lo_done_d = 1'b0;
                                                    if (!pad_word_last) pad_fsm_d = PAD80_LO_ONLY;
                                                end
                                                2'b00: begin
                                                    blk_data        = {padded32_hi, padded32_lo};
                                                    pad80_hi_done_d = 1'b1;
                                                    pad80_lo_done_d = 1'b1;
                                                    word_cnt_d      = pad_next_word_cnt;
                                                    pad_fsm_d       = pad_next_fsm;
                                                    blk_complete    = pad_next_complete;
                                                end
                                            endcase
                                        end
                                    endcase
                                end
                            endcase

                        end else begin
                            //---------------------------------------------------------
                            //  SHA-2-64 / SHA-3 / SHAKE stream
                            //---------------------------------------------------------
                            if (final_none) begin
                                blk_data = in_data_q;
                                if (pad_word_last) pad_fsm_d = PAD_WAIT_CORE;

                            end else if (in_bytes_q == 6'd8) begin
                                blk_data = in_data_q;
                                if (!pad_word_last) pad_fsm_d = PAD80_HI_ONLY;

                            end else begin
                                pad80_hi_done_d = 1'b1;
                                pad80_lo_done_d = 1'b1;

                                blk_data = apply_padding(in_data_q, in_bytes_q[2:0], domain_suffix);
                                if (pad_last_sha3) blk_data = blk_data | 64'h0000_0000_0000_0080;

                                word_cnt_d   = pad_next_word_cnt;
                                pad_fsm_d    = pad_next_fsm;
                                blk_complete = pad_next_complete;
                                blk_final    = pad_next_final;
                            end
                        end
                    end
                end

                PAD80_HI_ONLY: begin
                    if (mode_is_sha2_32 && !pad80_lo_done_q) begin
                        blk_write  = 1'b0;
                        word_cnt_d = word_cnt_q;
                        pad_fsm_d  = STREAM;
                    end else begin
                        blk_write = 1'b1;
                        blk_data  = pad_hi_word;

                        if (!mode_is_sha2_32) pad80_lo_done_d = 1'b1;
                        pad80_hi_done_d = 1'b1;

                        word_cnt_d   = pad_next_word_cnt;
                        pad_fsm_d    = pad_next_fsm;
                        blk_complete = pad_next_complete;
                        blk_final    = pad_next_final;

                        if (pad_last_sha3) blk_data = blk_data | 64'h0000_0000_0000_0080;
                    end
                end

                PAD80_LO_ONLY: begin
                    if (mode_is_sha2_32 && !pad80_hi_done_q) begin
                        blk_write  = 1'b0;
                        word_cnt_d = word_cnt_q;
                        pad_fsm_d  = STREAM;
                    end else begin
                        blk_write = 1'b1;
                        blk_data  = pad_lo_word;

                        if (!mode_is_sha2_32) pad80_hi_done_d = 1'b1;
                        pad80_lo_done_d = 1'b1;

                        word_cnt_d   = pad_next_word_cnt;
                        pad_fsm_d    = pad_next_fsm;
                        blk_complete = pad_next_complete;
                        blk_final    = pad_next_final;

                        if (pad_last_sha3) blk_data = blk_data | 64'h0000_0000_0000_0080;
                    end
                end

                PAD80_BOTH: begin
                    blk_write = 1'b1;
                    blk_data  = pad_both_word;

                    pad80_hi_done_d = 1'b1;
                    pad80_lo_done_d = 1'b1;

                    word_cnt_d   = pad_next_word_cnt;
                    pad_fsm_d    = pad_next_fsm;
                    blk_complete = pad_next_complete;
                    blk_final    = pad_next_final;

                    if (pad_last_sha3) blk_data = blk_data | 64'h0000_0000_0000_0080;
                end

                PAD_ZEROS: begin
                    blk_write = 1'b1;

                    blk_data  = pad_last_sha3 ? 64'h0000_0000_0000_0080 : 64'h0;
                    blk_final = pad_next_final;

                    word_cnt_d   = pad_next_word_cnt;
                    pad_fsm_d    = pad_next_fsm;
                    blk_complete = pad_next_complete;
                end

                LEN_FIELD: begin
                    blk_final  = 1'b1;
                    word_cnt_d = '0;
                    pad_fsm_d  = PAD_IDLE;

                    if (mode_is_sha2) begin
                        unique case (word_cnt_q)
                            5'd14: begin
                                blk_write  = 1'b1;
                                blk_data   = sha2_len_hi_word;
                                word_cnt_d = 5'd15;
                                pad_fsm_d  = LEN_FIELD;
                            end
                            5'd15: begin
                                blk_write    = 1'b1;
                                blk_data     = sha2_len_lo_word;
                                blk_complete = 1'b1;
                            end
                            default: begin
                                blk_write = 1'b0;
                            end
                        endcase
                    end else begin
                        blk_write    = 1'b1;
                        blk_data     = 64'h0000_0000_0000_0080;
                        blk_complete = 1'b1;
                    end
                end

                PAD_NEWBLOCK: begin
                    if(all_lanes_final) begin
                        word_cnt_d = '0;
                        if (core_stream_ready) begin
                            unique case ({pad80_hi_done_q, pad80_lo_done_q})
                                2'b11: pad_fsm_d = PAD_ZEROS;
                                2'b10: pad_fsm_d = PAD80_LO_ONLY;
                                2'b01: pad_fsm_d = PAD80_HI_ONLY;
                                2'b00: pad_fsm_d = PAD80_BOTH;
                            endcase
                        end
                    end else begin
                        pad_fsm_d = PAD_WAIT_CORE;
                    end
                end

                default: begin
                    pad_fsm_d = PAD_IDLE;
                end

            endcase
        end
    end

    always_ff @(posedge f_clk) begin
        if (!resetn) pad_fsm_q <= PAD_IDLE;
        else         pad_fsm_q <= pad_fsm_d;
    end

endmodule
