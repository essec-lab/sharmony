///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

module essec_sharmony_top
import essec_sharmony_pkg::*;
#(
    parameter bit REG_IO       = essec_sharmony_pkg::REG_IO_DEFAULT,
    parameter bit ROM_USE_BRAM = essec_sharmony_pkg::ROM_USE_BRAM_DEFAULT,
    parameter int ADDER_IMPL   = essec_sharmony_pkg::ADDER_IMPL_DEFAULT
)(
    input  logic            f_clk,
    input  logic            resetn,

    // control/config signals
    input  logic            start,
    input  logic            zeroize,
    input  mode_e           mode,
    output logic            busy,

    // load/save control
    input  logic            state_load,
    input  logic            state_save,
    input  logic            state_cache,

    // message stream inputs
    input  logic [63:0]     input_data,
    input  logic            input_valid,
    input  logic [5:0]      input_bytes,
    input  logic [1:0]      input_final,
    output logic            input_ready,

    // data stream outputs
    output logic [63:0]     output_data,
    output logic            output_valid,
    input  logic            output_ready
);

    mode_e mode_q;
    logic state_load_q;
    logic state_save_q;
    logic state_cache_q;

    logic [63:0] blk_data;
    logic blk_write;
    logic blk_final;
    logic blk_complete;

    logic rom_req;
    logic [7:0] rom_addr;
    logic [63:0] rom_rdata;

    logic core_stream_ready;
    logic pad_idle, core_idle;
    logic pad_idle_next, core_idle_next;

    logic start_sub;    // start delivered to submodules (REG_IO: registered, else raw)
    logic zeroize_sub /* verilator public_flat_rd */;  // active-zeroize delivered to submodules (probe)

    mode_e mode_d;
    assign mode_d = mode;

    logic state_load_d, state_save_d, state_cache_d;
    assign state_load_d = state_load;
    assign state_save_d = state_save;
    assign state_cache_d = state_cache;

generate
if (REG_IO) begin : g_reg_io
    //---------------------------------------------------------------------------------
    //  Buffered (registered-I/O) control plane
    //---------------------------------------------------------------------------------
    logic zeroize_q;
    logic zeroize_hold_q, zeroize_hold_d;
    logic [2:0] zeroize_idx_q,  zeroize_idx_d;
    logic [3:0] zeroize_state_d, zeroize_state_q;
    logic zeroize_active;
    logic busy_next;
    logic start_q;
    logic start_acc;

    assign {zeroize_hold_q, zeroize_idx_q} = zeroize_state_q;
    assign zeroize_state_d = {zeroize_hold_d, zeroize_idx_d};
    assign zeroize_active = zeroize_q | zeroize_hold_q;

    assign start_acc = start && !busy;

    assign busy_next = start_acc || zeroize || zeroize_active
                       || !pad_idle_next || !core_idle_next;

    always_ff @(posedge f_clk) begin
        if (!resetn) begin
            zeroize_q       <= 1'b0;
            start_q         <= 1'b0;
            busy            <= 1'b0;
            zeroize_state_q <= '0;
        end else begin
            zeroize_q       <= zeroize;
            start_q         <= start_acc;
            busy            <= busy_next;
            zeroize_state_q <= zeroize_state_d;
        end
    end

    always_ff @(posedge f_clk) begin
        if (!resetn) begin
            mode_q        <= mode_e'('0);
            state_load_q  <= 1'b0;
            state_save_q  <= 1'b0;
            state_cache_q <= 1'b0;
        end else if (start && !busy) begin
            mode_q        <= mode_d;
            state_load_q  <= state_load_d;
            // Resume-wins at the latch: a save requested together with a cache-resume
            state_save_q  <= state_save_d && !(state_load_d && state_cache_d);
            state_cache_q <= state_cache_d;
        end
    end

    always_comb begin
        zeroize_hold_d = zeroize_hold_q;
        zeroize_idx_d  = zeroize_idx_q;

        if (zeroize_q) begin
            zeroize_hold_d = 1'b1;
            zeroize_idx_d  = ZEROIZE_IDX - 3'd1;
        end else if (zeroize_hold_q) begin
            if (zeroize_idx_q == '0) begin
                zeroize_hold_d = 1'b0;
            end else begin
                zeroize_idx_d = zeroize_idx_q - 3'd1;
            end
        end
    end

    assign start_sub   = start_q;
    assign zeroize_sub = zeroize_active;

    logic [1:0] idle_unused;
    assign idle_unused = {pad_idle, core_idle};

end else begin : g_comb_io
    //---------------------------------------------------------------------------------
    //  Combinational (no-I/O-buffer) control plane
    //---------------------------------------------------------------------------------
    logic zeroize_active_d, zeroize_active_q;
    logic [2:0] zeroize_idx_d,    zeroize_idx_q;
    logic [3:0] zeroize_state_d,  zeroize_state_q;
    logic busy_comb;
    logic mode_we;

    assign {zeroize_active_q, zeroize_idx_q} = zeroize_state_q;
    assign zeroize_state_d = {zeroize_active_d, zeroize_idx_d};

    assign busy_comb = zeroize_active_q || !pad_idle || !core_idle;
    assign busy      = busy_comb;
    assign mode_we   = !busy_comb;

    always_ff @(posedge f_clk) begin
        if (!resetn) begin
            mode_q        <= mode_e'('0);
            state_load_q  <= 1'b0;
            state_save_q  <= 1'b0;
            state_cache_q <= 1'b0;
        end else if (mode_we) begin
            mode_q        <= mode_d;
            state_load_q  <= state_load_d;
            // Resume-wins at the latch: a save requested together with a cache-resume
            state_save_q  <= state_save_d && !(state_load_d && state_cache_d);
            state_cache_q <= state_cache_d;
        end
    end

    always_ff @(posedge f_clk) begin
        if (!resetn)         zeroize_state_q <= '0;
        else                 zeroize_state_q <= zeroize_state_d;
    end

    always_comb begin
        zeroize_active_d = zeroize_active_q;
        zeroize_idx_d    = zeroize_idx_q;

        if (zeroize && !zeroize_active_q) begin
            zeroize_active_d = 1'b1;
            zeroize_idx_d    = ZEROIZE_IDX;
        end else if (zeroize_active_q) begin
            if (zeroize_idx_q == '0) begin
                zeroize_active_d = 1'b0;
            end else begin
                zeroize_idx_d = zeroize_idx_q - 3'd1;
            end
        end
    end

    assign start_sub   = start && !busy_comb;
    assign zeroize_sub = zeroize_active_q;

    logic [1:0] idle_next_unused;
    assign idle_next_unused = {pad_idle_next, core_idle_next};
end
endgenerate

    essec_sharmony_pad #(.REG_IO(REG_IO)) pad_inst (
        .f_clk(f_clk),
        .resetn(resetn),
        .start(start_sub),
        .zeroize(zeroize_sub),
        .mode(mode_q),
        .state_load(state_load_q),
        .state_save(state_save_q),
        .state_cache(state_cache_q),
        .input_data(input_data),
        .input_bytes(input_bytes),
        .input_final(input_final),
        .input_valid(input_valid),
        .input_ready(input_ready),
        .blk_data(blk_data),
        .blk_write(blk_write),
        .blk_final(blk_final),
        .blk_complete(blk_complete),
        .core_stream_ready(core_stream_ready),
        .pad_idle(pad_idle),
        .pad_idle_next(pad_idle_next)
    );

    essec_sharmony_core #(.REG_IO(REG_IO), .ADDER_IMPL(ADDER_IMPL)) core_inst (
        .f_clk(f_clk),
        .resetn(resetn),
        .start(start_sub),
        .zeroize(zeroize_sub),
        .mode(mode_q),
        .state_load(state_load_q),
        .state_save(state_save_q),
        .state_cache(state_cache_q),
        .blk_data(blk_data),
        .blk_write(blk_write),
        .blk_final(blk_final),
        .blk_complete(blk_complete),
        .rom_req(rom_req),
        .rom_addr(rom_addr),
        .rom_rdata(rom_rdata),
        .output_data(output_data),
        .output_valid(output_valid),
        .output_ready(output_ready),
        .stream_ready(core_stream_ready),
        .core_idle(core_idle),
        .core_idle_next(core_idle_next)
    );

    essec_sharmony_rom #(.ROM_USE_BRAM(ROM_USE_BRAM)) constants_rom (
        .f_clk (f_clk),
        .rd_en (rom_req),
        .addr  (rom_addr),
        .dout  (rom_rdata)
    );

endmodule
