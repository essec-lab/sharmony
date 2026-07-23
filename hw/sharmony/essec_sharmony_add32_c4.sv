///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

module essec_sharmony_add32_c4 (
    input  logic [31:0] a,
    input  logic [31:0] b,
    input  logic        cin,
    output logic [31:0] sum,
    output logic        cout
`ifdef THETA_ADDER_XOR
   ,output logic [31:0] pout   // carry-propagate XOR tap (a ^ b), reused for SHA-3 theta
`endif
);
    logic [7:0] carry;

    essec_sharmony_add4_c4 u_add4_0 (
        .a    (a[3:0]),
        .b    (b[3:0]),
        .cin  (cin),
        .sum  (sum[3:0]),
        .cout (carry[0])
`ifdef THETA_ADDER_XOR
       ,.pout (pout[3:0])
`endif
    );

    genvar i;
    generate
        for (i = 1; i < 8; i = i + 1) begin : gen_add4
            essec_sharmony_add4_c4 u_add4 (
                .a    (a[4*i+3 : 4*i]),
                .b    (b[4*i+3 : 4*i]),
                .cin   (carry[i-1]),
                .sum  (sum[4*i+3 : 4*i]),
                .cout   (carry[i])
`ifdef THETA_ADDER_XOR
               ,.pout (pout[4*i+3 : 4*i])
`endif
            );
        end
    endgenerate

    assign cout = carry[7];
endmodule
