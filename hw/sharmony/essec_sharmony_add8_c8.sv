///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

module essec_sharmony_add8_c8 (
    input  logic [7:0] a,
    input  logic [7:0] b,
    input  logic       cin,
    output logic [7:0] sum,
    output logic       cout
`ifdef THETA_ADDER_XOR
   ,output logic [7:0] pout   // carry-propagate XOR tap (a ^ b), reused for SHA-3 theta
`endif
);
    logic [7:0] prop;
    logic [6:0] co_bus_unused;   // CO[6:0]: intermediate carries, intentionally unused

    assign prop = a ^ b;
`ifdef THETA_ADDER_XOR
    assign pout = prop;
`endif

    CARRY8 #(
        .CARRY_TYPE("SINGLE_CY8")
    ) carry8_inst (
        .CO    ({cout, co_bus_unused}),
        .O     (sum),
        .CI    (cin),
        .CI_TOP(1'b0),
        .DI    (b),
        .S     (prop)
    );

endmodule
