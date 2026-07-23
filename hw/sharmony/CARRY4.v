///////////////////////////////////////////////////////////////////////////////
//     Copyright (c) 1995/2018 Xilinx, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//  Modified file -- notice per Apache License 2.0, Section 4(b):
//  Source  : https://github.com/Xilinx/XilinxUnisimLibrary
//            (verilog/src/unisims/CARRY4.v); otherwise unmodified.
//  Changes : ESSEC Lab, 2026-07-21 --
//   1) removed the "!== 1'bz" receiver-value guards on the input pins so the
//      model elaborates under the two-state simulator Verilator ('z' cannot
//      occur in two-state simulation, so the guards are identities there and
//      simulated behavior is unchanged);
//   2) added the two Verilator lint_off metacomments below, waiving -Wall
//      notes on unisim-internal constructs (the unused MODULE_NAME constant
//      and the XIL_XECLIB-mode glblGSR register). Metacomments are plain
//      comments to every other tool;
//   3) defined XIL_XECLIB below (Xilinx's own switch for compiled-library
//      use) so the file's simulator-neutral branch is selected: no glbl
//      hierarchy reference and no specify blocks;
//   4) removed the timescale directive: the SHARMONY sources declare no
//      timescale, and a design must not mix timescaled and timescale-less
//      modules (IEEE 1800 3.14.2.3). Cycle-based simulation is unaffected.
///////////////////////////////////////////////////////////////////////////////
`ifndef XIL_XECLIB
`define XIL_XECLIB
`endif
/* verilator lint_off UNUSEDPARAM */
/* verilator lint_off UNUSEDSIGNAL */
//   ____  ____
//  /   /\/   /
// /___/  \  /     Vendor      : Xilinx
// \   \   \/      Version     : 2018.1
//  \   \          Description : Xilinx Unified Simulation Library Component
//  /   /                        Fast Carry Logic with Look Ahead
// /___/   /\      Filename    : CARRY4.v
// \   \  /  \
//  \___\/\___\
//
///////////////////////////////////////////////////////////////////////////////
//  Revision:
//    04/11/05 - Initial version.
//    05/06/05 - Unused CYINT or CI pin need grounded instead of open (CR207752)
//    05/31/05 - Change pin order, remove connection check for CYINIT and CI.
//    12/21/05 - Add timing path.
//    04/13/06 - Add full timing path for DI to O (CR228786)
//    06/04/07 - Add wire definition.
//    12/13/11 - Added `celldefine and `endcelldefine (CR 524859).
//    04/13/12 - CR655410 - add pulldown, CI, CYINIT, sync uni/sim/unp
//  End Revision:
///////////////////////////////////////////////////////////////////////////////

`celldefine

module CARRY4 
`ifdef XIL_TIMING
#(
  parameter LOC = "UNPLACED"
)
`endif
(
  output [3:0] CO,
  output [3:0] O,

  input CI,
  input CYINIT,
  input [3:0] DI,
  input [3:0] S
);
  
// define constants
  localparam MODULE_NAME = "CARRY4";

`ifdef XIL_XECLIB
  reg glblGSR = 1'b0;
`else
  tri0 glblGSR = glbl.GSR;
`endif

  wire CI_in;
  wire CYINIT_in;
  wire [3:0] DI_in;
  wire [3:0] S_in;

  assign CI_in = CI;
  assign CYINIT_in = CYINIT;
  assign DI_in = DI;
  assign S_in = S;

// begin behavioral model

  wire [3:0] CO_fb;
  assign CO_fb = {CO[2:0], CI_in || CYINIT_in};
  assign O = S_in ^ CO_fb;
  assign CO = (S_in & CO_fb) | (~S_in & DI_in);

// end behavioral model

`ifndef XIL_XECLIB
`ifdef XIL_TIMING
  specify
    (CI => CO[0]) = (0:0:0, 0:0:0);
    (CI => CO[1]) = (0:0:0, 0:0:0);
    (CI => CO[2]) = (0:0:0, 0:0:0);
    (CI => CO[3]) = (0:0:0, 0:0:0);
    (CI => O[0]) = (0:0:0, 0:0:0);
    (CI => O[1]) = (0:0:0, 0:0:0);
    (CI => O[2]) = (0:0:0, 0:0:0);
    (CI => O[3]) = (0:0:0, 0:0:0);
    (CYINIT => CO[0]) = (0:0:0, 0:0:0);
    (CYINIT => CO[1]) = (0:0:0, 0:0:0);
    (CYINIT => CO[2]) = (0:0:0, 0:0:0);
    (CYINIT => CO[3]) = (0:0:0, 0:0:0);
    (CYINIT => O[0]) = (0:0:0, 0:0:0);
    (CYINIT => O[1]) = (0:0:0, 0:0:0);
    (CYINIT => O[2]) = (0:0:0, 0:0:0);
    (CYINIT => O[3]) = (0:0:0, 0:0:0);
    (DI[0] => CO[0]) = (0:0:0, 0:0:0);
    (DI[0] => CO[1]) = (0:0:0, 0:0:0);
    (DI[0] => CO[2]) = (0:0:0, 0:0:0);
    (DI[0] => CO[3]) = (0:0:0, 0:0:0);
    (DI[0] => O[0]) = (0:0:0, 0:0:0);
    (DI[0] => O[1]) = (0:0:0, 0:0:0);
    (DI[0] => O[2]) = (0:0:0, 0:0:0);
    (DI[0] => O[3]) = (0:0:0, 0:0:0);
    (DI[1] => CO[0]) = (0:0:0, 0:0:0);
    (DI[1] => CO[1]) = (0:0:0, 0:0:0);
    (DI[1] => CO[2]) = (0:0:0, 0:0:0);
    (DI[1] => CO[3]) = (0:0:0, 0:0:0);
    (DI[1] => O[0]) = (0:0:0, 0:0:0);
    (DI[1] => O[1]) = (0:0:0, 0:0:0);
    (DI[1] => O[2]) = (0:0:0, 0:0:0);
    (DI[1] => O[3]) = (0:0:0, 0:0:0);
    (DI[2] => CO[0]) = (0:0:0, 0:0:0);
    (DI[2] => CO[1]) = (0:0:0, 0:0:0);
    (DI[2] => CO[2]) = (0:0:0, 0:0:0);
    (DI[2] => CO[3]) = (0:0:0, 0:0:0);
    (DI[2] => O[0]) = (0:0:0, 0:0:0);
    (DI[2] => O[1]) = (0:0:0, 0:0:0);
    (DI[2] => O[2]) = (0:0:0, 0:0:0);
    (DI[2] => O[3]) = (0:0:0, 0:0:0);
    (DI[3] => CO[0]) = (0:0:0, 0:0:0);
    (DI[3] => CO[1]) = (0:0:0, 0:0:0);
    (DI[3] => CO[2]) = (0:0:0, 0:0:0);
    (DI[3] => CO[3]) = (0:0:0, 0:0:0);
    (DI[3] => O[0]) = (0:0:0, 0:0:0);
    (DI[3] => O[1]) = (0:0:0, 0:0:0);
    (DI[3] => O[2]) = (0:0:0, 0:0:0);
    (DI[3] => O[3]) = (0:0:0, 0:0:0);
    (S[0] => CO[0]) = (0:0:0, 0:0:0);
    (S[0] => CO[1]) = (0:0:0, 0:0:0);
    (S[0] => CO[2]) = (0:0:0, 0:0:0);
    (S[0] => CO[3]) = (0:0:0, 0:0:0);
    (S[0] => O[0]) = (0:0:0, 0:0:0);
    (S[0] => O[1]) = (0:0:0, 0:0:0);
    (S[0] => O[2]) = (0:0:0, 0:0:0);
    (S[0] => O[3]) = (0:0:0, 0:0:0);
    (S[1] => CO[0]) = (0:0:0, 0:0:0);
    (S[1] => CO[1]) = (0:0:0, 0:0:0);
    (S[1] => CO[2]) = (0:0:0, 0:0:0);
    (S[1] => CO[3]) = (0:0:0, 0:0:0);
    (S[1] => O[0]) = (0:0:0, 0:0:0);
    (S[1] => O[1]) = (0:0:0, 0:0:0);
    (S[1] => O[2]) = (0:0:0, 0:0:0);
    (S[1] => O[3]) = (0:0:0, 0:0:0);
    (S[2] => CO[0]) = (0:0:0, 0:0:0);
    (S[2] => CO[1]) = (0:0:0, 0:0:0);
    (S[2] => CO[2]) = (0:0:0, 0:0:0);
    (S[2] => CO[3]) = (0:0:0, 0:0:0);
    (S[2] => O[0]) = (0:0:0, 0:0:0);
    (S[2] => O[1]) = (0:0:0, 0:0:0);
    (S[2] => O[2]) = (0:0:0, 0:0:0);
    (S[2] => O[3]) = (0:0:0, 0:0:0);
    (S[3] => CO[0]) = (0:0:0, 0:0:0);
    (S[3] => CO[1]) = (0:0:0, 0:0:0);
    (S[3] => CO[2]) = (0:0:0, 0:0:0);
    (S[3] => CO[3]) = (0:0:0, 0:0:0);
    (S[3] => O[0]) = (0:0:0, 0:0:0);
    (S[3] => O[1]) = (0:0:0, 0:0:0);
    (S[3] => O[2]) = (0:0:0, 0:0:0);
    (S[3] => O[3]) = (0:0:0, 0:0:0);
    specparam PATHPULSE$ = 0;
  endspecify
`endif
`endif
endmodule

`endcelldefine
