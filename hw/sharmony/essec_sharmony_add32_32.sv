///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Dual-mode adder: one 64-bit add (mode=1) or two independent 32-bit adds
// (mode=0, both halves taking `cin`). The carry between the low and high 32-bit
// halves is gated by `mode`.
//
// The carry-chain implementation is selected by essec_sharmony_pkg::ADDER_IMPL:
//  ADDER_GENERIC    : portable behavioral '+'        (any FPGA family / ASIC)
//  ADDER_CARRY4     : Xilinx 7-series CARRY4         (default)
//  ADDER_CARRY8     : UltraScale/UltraScale+ CARRY8  (UltraScale-class parts)
//
///////////////////////////////////////////////////////////////////////////////////////

module essec_sharmony_add32_32
    import essec_sharmony_pkg::*;
#(
    parameter int ADDER_IMPL = essec_sharmony_pkg::ADDER_IMPL_DEFAULT
)(
    input  logic [63:0] a,
    input  logic [63:0] b,
    input  logic        cin,
    input  logic        mode,
    output logic [63:0] sum
`ifdef THETA_ADDER_XOR
   ,output logic [63:0] pout   // carry-propagate XOR tap (a ^ b), reused for SHA-3 theta
`endif
);

    generate case (ADDER_IMPL)
    //---------------------------------------------------------------------------------
    //  ADDER_GENERIC: portable behavioral implementation
    //---------------------------------------------------------------------------------
    // The synthesis tool infers whatever carry resource the target device provides.
    ADDER_GENERIC: begin : g_generic
        logic [32:0] add_lo;
        assign add_lo = {1'b0, a[31:0]}  + {1'b0, b[31:0]}  + {32'b0, cin};
        logic cout_lo;
        assign cout_lo = add_lo[32];
        logic cin_hi;
        assign cin_hi = mode ? cout_lo : cin;
        logic [32:0] add_hi;
        assign add_hi = {1'b0, a[63:32]} + {1'b0, b[63:32]} + {32'b0, cin_hi};

        assign sum  = {add_hi[31:0], add_lo[31:0]};
        logic unused_cout;
        assign unused_cout = add_hi[32];   // high carry-out not needed (cout removed)
`ifdef THETA_ADDER_XOR
        // Behavioral propagate tap; on FPGA the tool merges it with the inferred
        // adder's propagate row.
        assign pout = a ^ b;
`endif
    end

    //---------------------------------------------------------------------------------
    //  ADDER_CARRY4 (default value): Xilinx 7-series CARRY4 carry chain
    //---------------------------------------------------------------------------------
    // A MUXCY gates the inter-half carry (no LUT for the mode mux).
    ADDER_CARRY4: begin : g_carry4
        logic [31:0] sum_lo, sum_hi;
        logic cout_lo;
        logic cout_hi_unused;   // high-half carry-out not needed (cout removed)
        logic cin_hi;

        essec_sharmony_add32_c4 u_lo (
            .a   (a[31:0]),
            .b   (b[31:0]),
            .cin (cin),
            .sum (sum_lo),
            .cout(cout_lo)
`ifdef THETA_ADDER_XOR
           ,.pout(pout[31:0])
`endif
        );

        // Gate the carry between low32 and high32 using carry logic (not a LUT).
        MUXCY u_carry_gate (
            .CI(cout_lo),
            .DI(cin),
            .S (mode),
            .O (cin_hi)
        );

        essec_sharmony_add32_c4 u_hi (
            .a   (a[63:32]),
            .b   (b[63:32]),
            .cin (cin_hi),
            .sum (sum_hi),
            .cout(cout_hi_unused)
`ifdef THETA_ADDER_XOR
           ,.pout(pout[63:32])
`endif
        );

        assign sum = {sum_hi, sum_lo};
    end

    //---------------------------------------------------------------------------------
    //  ADDER_CARRY8: UltraScale/UltraScale+ CARRY8 carry chain
    //---------------------------------------------------------------------------------
    // UltraScale has no standalone MUXCY, but a single CARRY8 bit IS a
    // carry-chain mux (CO[0] = S[0] ? CI : DI[0]); we use one to gate the
    // inter-half carry on dedicated carry logic instead of a LUT. NOT
    // synthesizable on 7-series.
    ADDER_CARRY8: begin : g_carry8
        logic [31:0] sum_lo, sum_hi;
        logic cout_lo;
        logic cout_hi_unused;   // high-half carry-out not needed (cout removed)
        logic cin_hi;

        essec_sharmony_add32_c8 u_lo (
            .a   (a[31:0]),
            .b   (b[31:0]),
            .cin (cin),
            .sum (sum_lo),
            .cout(cout_lo)
`ifdef THETA_ADDER_XOR
           ,.pout(pout[31:0])
`endif
        );

        // Gate the carry between low32 and high32 on the CARRY8 carry chain
        // (not a LUT). Bit 0 computes CO[0] = S[0] ? CI : DI[0] = mode ? cout_lo
        // : cin. Upper 7 bits are tied off; their CO/O outputs are unused.
        logic gate_cin_hi;
        logic [6:0] gate_co_unused;   // CO[7:1] unused
        logic [7:0] gate_o_unused;    // O[7:0] (sum bits) unused
        CARRY8 #(
            .CARRY_TYPE("SINGLE_CY8")
        ) u_carry_gate (
            .CO    ({gate_co_unused, gate_cin_hi}),  // CO[0] = mode ? cout_lo : cin
            .O     (gate_o_unused),
            .CI    (cout_lo),
            .CI_TOP(1'b0),
            .DI    ({7'b0, cin}),    // DI[0] = cin   (injected when mode=0)
            .S     ({7'b0, mode})    // S[0]  = mode  (propagate cout_lo when mode=1)
        );

        assign cin_hi = gate_cin_hi;

        essec_sharmony_add32_c8 u_hi (
            .a   (a[63:32]),
            .b   (b[63:32]),
            .cin (cin_hi),
            .sum (sum_hi),
            .cout(cout_hi_unused)
`ifdef THETA_ADDER_XOR
           ,.pout(pout[63:32])
`endif
        );

        assign sum = {sum_hi, sum_lo};
    end

    endcase
    endgenerate

endmodule
