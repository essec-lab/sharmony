///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// essec_sharmony_rom: registered-read ROM of the SHA-2 (K) and SHA-3 (iota RC)
// round constants. Implementation is selected by ROM_USE_BRAM in essec_sharmony_pkg:
//   ROM_USE_BRAM = 1 -> block RAM   (rom_style="block")
//                = 0 -> distributed (rom_style="distributed", LUTRAM)
//
///////////////////////////////////////////////////////////////////////////////////////

    module essec_sharmony_rom
        import essec_sharmony_pkg::*;
    #(
        parameter int N = 168,
        parameter bit ROM_USE_BRAM = essec_sharmony_pkg::ROM_USE_BRAM_DEFAULT,
        localparam int AW = (N <= 1) ? 1 : $clog2(N)
    )(
        input  logic          f_clk,
        input  logic          rd_en,
        input  logic [AW-1:0] addr,
        output logic [63:0]   dout
    );

    localparam logic [63:0] ROM_DATA [0:N-1] = '{
        64'h428a2f98428a2f98,   // 0
        64'h7137449171374491,   // 1
        64'hb5c0fbcfb5c0fbcf,   // 2
        64'he9b5dba5e9b5dba5,   // 3
        64'h3956c25b3956c25b,   // 4
        64'h59f111f159f111f1,   // 5
        64'h923f82a4923f82a4,   // 6
        64'hab1c5ed5ab1c5ed5,   // 7
        64'hd807aa98d807aa98,   // 8
        64'h12835b0112835b01,   // 9
        64'h243185be243185be,   // 10
        64'h550c7dc3550c7dc3,   // 11
        64'h72be5d7472be5d74,   // 12
        64'h80deb1fe80deb1fe,   // 13
        64'h9bdc06a79bdc06a7,   // 14
        64'hc19bf174c19bf174,   // 15
        64'he49b69c1e49b69c1,   // 16
        64'hefbe4786efbe4786,   // 17
        64'h0fc19dc60fc19dc6,   // 18
        64'h240ca1cc240ca1cc,   // 19
        64'h2de92c6f2de92c6f,   // 20
        64'h4a7484aa4a7484aa,   // 21
        64'h5cb0a9dc5cb0a9dc,   // 22
        64'h76f988da76f988da,   // 23
        64'h983e5152983e5152,   // 24
        64'ha831c66da831c66d,   // 25
        64'hb00327c8b00327c8,   // 26
        64'hbf597fc7bf597fc7,   // 27
        64'hc6e00bf3c6e00bf3,   // 28
        64'hd5a79147d5a79147,   // 29
        64'h06ca635106ca6351,   // 30
        64'h1429296714292967,   // 31
        64'h27b70a8527b70a85,   // 32
        64'h2e1b21382e1b2138,   // 33
        64'h4d2c6dfc4d2c6dfc,   // 34
        64'h53380d1353380d13,   // 35
        64'h650a7354650a7354,   // 36
        64'h766a0abb766a0abb,   // 37
        64'h81c2c92e81c2c92e,   // 38
        64'h92722c8592722c85,   // 39
        64'ha2bfe8a1a2bfe8a1,   // 40
        64'ha81a664ba81a664b,   // 41
        64'hc24b8b70c24b8b70,   // 42
        64'hc76c51a3c76c51a3,   // 43
        64'hd192e819d192e819,   // 44
        64'hd6990624d6990624,   // 45
        64'hf40e3585f40e3585,   // 46
        64'h106aa070106aa070,   // 47
        64'h19a4c11619a4c116,   // 48
        64'h1e376c081e376c08,   // 49
        64'h2748774c2748774c,   // 50
        64'h34b0bcb534b0bcb5,   // 51
        64'h391c0cb3391c0cb3,   // 52
        64'h4ed8aa4a4ed8aa4a,   // 53
        64'h5b9cca4f5b9cca4f,   // 54
        64'h682e6ff3682e6ff3,   // 55
        64'h748f82ee748f82ee,   // 56
        64'h78a5636f78a5636f,   // 57
        64'h84c8781484c87814,   // 58
        64'h8cc702088cc70208,   // 59
        64'h90befffa90befffa,   // 60
        64'ha4506ceba4506ceb,   // 61
        64'hbef9a3f7bef9a3f7,   // 62
        64'hc67178f2c67178f2,   // 63
        64'h428a2f98d728ae22,   // 64
        64'h7137449123ef65cd,   // 65
        64'hb5c0fbcfec4d3b2f,   // 66
        64'he9b5dba58189dbbc,   // 67
        64'h3956c25bf348b538,   // 68
        64'h59f111f1b605d019,   // 69
        64'h923f82a4af194f9b,   // 70
        64'hab1c5ed5da6d8118,   // 71
        64'hd807aa98a3030242,   // 72
        64'h12835b0145706fbe,   // 73
        64'h243185be4ee4b28c,   // 74
        64'h550c7dc3d5ffb4e2,   // 75
        64'h72be5d74f27b896f,   // 76
        64'h80deb1fe3b1696b1,   // 77
        64'h9bdc06a725c71235,   // 78
        64'hc19bf174cf692694,   // 79
        64'he49b69c19ef14ad2,   // 80
        64'hefbe4786384f25e3,   // 81
        64'h0fc19dc68b8cd5b5,   // 82
        64'h240ca1cc77ac9c65,   // 83
        64'h2de92c6f592b0275,   // 84
        64'h4a7484aa6ea6e483,   // 85
        64'h5cb0a9dcbd41fbd4,   // 86
        64'h76f988da831153b5,   // 87
        64'h983e5152ee66dfab,   // 88
        64'ha831c66d2db43210,   // 89
        64'hb00327c898fb213f,   // 90
        64'hbf597fc7beef0ee4,   // 91
        64'hc6e00bf33da88fc2,   // 92
        64'hd5a79147930aa725,   // 93
        64'h06ca6351e003826f,   // 94
        64'h142929670a0e6e70,   // 95
        64'h27b70a8546d22ffc,   // 96
        64'h2e1b21385c26c926,   // 97
        64'h4d2c6dfc5ac42aed,   // 98
        64'h53380d139d95b3df,   // 99
        64'h650a73548baf63de,   // 100
        64'h766a0abb3c77b2a8,   // 101
        64'h81c2c92e47edaee6,   // 102
        64'h92722c851482353b,   // 103
        64'ha2bfe8a14cf10364,   // 104
        64'ha81a664bbc423001,   // 105
        64'hc24b8b70d0f89791,   // 106
        64'hc76c51a30654be30,   // 107
        64'hd192e819d6ef5218,   // 108
        64'hd69906245565a910,   // 109
        64'hf40e35855771202a,   // 110
        64'h106aa07032bbd1b8,   // 111
        64'h19a4c116b8d2d0c8,   // 112
        64'h1e376c085141ab53,   // 113
        64'h2748774cdf8eeb99,   // 114
        64'h34b0bcb5e19b48a8,   // 115
        64'h391c0cb3c5c95a63,   // 116
        64'h4ed8aa4ae3418acb,   // 117
        64'h5b9cca4f7763e373,   // 118
        64'h682e6ff3d6b2b8a3,   // 119
        64'h748f82ee5defb2fc,   // 120
        64'h78a5636f43172f60,   // 121
        64'h84c87814a1f0ab72,   // 122
        64'h8cc702081a6439ec,   // 123
        64'h90befffa23631e28,   // 124
        64'ha4506cebde82bde9,   // 125
        64'hbef9a3f7b2c67915,   // 126
        64'hc67178f2e372532b,   // 127
        64'hca273eceea26619c,   // 128
        64'hd186b8c721c0c207,   // 129
        64'heada7dd6cde0eb1e,   // 130
        64'hf57d4f7fee6ed178,   // 131
        64'h06f067aa72176fba,   // 132
        64'h0a637dc5a2c898a6,   // 133
        64'h113f9804bef90dae,   // 134
        64'h1b710b35131c471b,   // 135
        64'h28db77f523047d84,   // 136
        64'h32caab7b40c72493,   // 137
        64'h3c9ebe0a15c9bebc,   // 138
        64'h431d67c49c100d4c,   // 139
        64'h4cc5d4becb3e42b6,   // 140
        64'h597f299cfc657e2a,   // 141
        64'h5fcb6fab3ad6faec,   // 142
        64'h6c44198c4a475817,   // 143
        64'h0000000000000001,   // 144
        64'h0000000000008082,   // 145
        64'h800000000000808a,   // 146
        64'h8000000080008000,   // 147
        64'h000000000000808b,   // 148
        64'h0000000080000001,   // 149
        64'h8000000080008081,   // 150
        64'h8000000000008009,   // 151
        64'h000000000000008a,   // 152
        64'h0000000000000088,   // 153
        64'h0000000080008009,   // 154
        64'h000000008000000a,   // 155
        64'h000000008000808b,   // 156
        64'h800000000000008b,   // 157
        64'h8000000000008089,   // 158
        64'h8000000000008003,   // 159
        64'h8000000000008002,   // 160
        64'h8000000000000080,   // 161
        64'h000000000000800a,   // 162
        64'h800000008000000a,   // 163
        64'h8000000080008081,   // 164
        64'h8000000000008080,   // 165
        64'h0000000080000001,   // 166
        64'h8000000080008008    // 167
    };

    generate
        if (ROM_USE_BRAM) begin : g_bram
            (* rom_style = "block" *) logic [63:0] mem [0:N-1] = ROM_DATA;
            always_ff @(posedge f_clk)
                if (rd_en) dout <= mem[addr];
        end else begin : g_dist
            (* rom_style = "distributed" *) logic [63:0] mem [0:N-1] = ROM_DATA;
            always_ff @(posedge f_clk)
                if (rd_en) dout <= mem[addr];
        end
    endgenerate

endmodule
