///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

module essec_sharmony_add32_c8 (
    input  logic [31:0] a,
    input  logic [31:0] b,
    input  logic        cin,
    output logic [31:0] sum,
    output logic        cout
`ifdef THETA_ADDER_XOR
   ,output logic [31:0] pout   // carry-propagate XOR tap (a ^ b), reused for SHA-3 theta
`endif
);
    logic [3:0] carry;

    essec_sharmony_add8_c8 u_add8_0 (
        .a    (a[7:0]),
        .b    (b[7:0]),
        .cin  (cin),
        .sum  (sum[7:0]),
        .cout (carry[0])
`ifdef THETA_ADDER_XOR
       ,.pout (pout[7:0])
`endif
    );

    genvar i;
    generate
        for (i = 1; i < 4; i = i + 1) begin : gen_add8
            essec_sharmony_add8_c8 u_add8 (
                .a    (a[8*i+7 : 8*i]),
                .b    (b[8*i+7 : 8*i]),
                .cin  (carry[i-1]),
                .sum  (sum[8*i+7 : 8*i]),
                .cout (carry[i])
`ifdef THETA_ADDER_XOR
               ,.pout (pout[8*i+7 : 8*i])
`endif
            );
        end
    endgenerate

    assign cout = carry[3];
endmodule
