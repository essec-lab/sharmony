# /////////////////////////////////////////////////////////////////////////////////////
# //
# // Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
# // Licensed under the Apache License, Version 2.0, see LICENSE for details.
# // SPDX-License-Identifier: Apache-2.0
# //
# /////////////////////////////////////////////////////////////////////////////////////
# //
# // Out-of-context Vivado synthesis for essec_sharmony_top (xc7a200tfbg484-3,
# // 10 ns f_clk, timing-driven: the clock is read_xdc'd before synth_design).
# // Emits utilization/timing reports plus the tagged report.dat consumed by
# // synth/vivado_tables.awk. Invoked by `make synth-vivado`.
# //
# /////////////////////////////////////////////////////////////////////////////////////

set REPO_ROOT [file normalize [file join [file dirname [info script]] .. ..]]
set OUT_DIR   [file join $REPO_ROOT synth work]
file mkdir $OUT_DIR

set PART xc7a200tfbg484-3
set TOP  essec_sharmony_top

set SRCS [list \
  hw/sharmony/essec_sharmony_pkg.sv \
  hw/sharmony/essec_sharmony_add4_c4.sv \
  hw/sharmony/essec_sharmony_add32_c4.sv \
  hw/sharmony/essec_sharmony_add32_32.sv \
  hw/sharmony/essec_sharmony_rom.sv \
  hw/sharmony/essec_sharmony_pad.sv \
  hw/sharmony/essec_sharmony_core.sv \
  hw/sharmony/essec_sharmony_top.sv \
]

foreach f $SRCS { read_verilog -sv [file join $REPO_ROOT $f] }
read_xdc [file join $REPO_ROOT synth sharmony_top sharmony_top.xdc]

synth_design -top $TOP -part $PART -mode out_of_context

write_checkpoint        -force [file join $OUT_DIR ${TOP}_synth.dcp]
report_timing_summary  -file   [file join $OUT_DIR timing_summary.rpt]
report_utilization     -file   [file join $OUT_DIR utilization.rpt]
report_utilization -hierarchical -hierarchical_depth 4 -file [file join $OUT_DIR hier_util.rpt]
report_clock_utilization -file [file join $OUT_DIR clock_util.rpt]

set prim_rpt [open [file join $OUT_DIR primitives.rpt] w]
puts $prim_rpt "Primitive cell counts across the whole design:"
puts $prim_rpt ""
foreach prim {CARRY4 MUXCY XORCY LUT6_2 LUT6 LUT5 LUT4 LUT3 LUT2 LUT1 FDRE FDCE FDSE FDPE RAMB36E1 RAMB18E1 DSP48E1 MUXF7 MUXF8} {
    set cnt [llength [get_cells -hierarchical -quiet -filter "REF_NAME == $prim"]]
    if {$cnt > 0} { puts $prim_rpt [format "  %-10s %6d" $prim $cnt] }
}
puts $prim_rpt ""
puts $prim_rpt "Per-instance primitive breakdown for the 12 swapped adders:"
foreach inst_name {add_d0 add_d1 add_Wt add_Wt_Kt add_h_sigma1 add_t1_d add_t2 add_h_s1_ch add_t1_all add_t1_plus_t2 add_H3_plus_A add_H7_plus_E} {
    puts $prim_rpt ""
    puts $prim_rpt "  $inst_name:"
    foreach prim {CARRY4 MUXCY XORCY LUT6_2 LUT6 LUT5 LUT4 LUT3 LUT2 LUT1} {
        set cnt [llength [get_cells -hierarchical -quiet -filter "REF_NAME == $prim && NAME =~ *${inst_name}/*"]]
        if {$cnt > 0} { puts $prim_rpt [format "    %-10s %6d" $prim $cnt] }
    }
}
close $prim_rpt

# ============================================================================
# Machine-readable data for the resource / timing / I/O tables printed by
# `make synth-vivado` (formatted by synth/vivado_tables.awk).
# ============================================================================
set dat [open [file join $OUT_DIR report.dat] w]

set util_txt [report_utilization -return_string]
# 'Used' value for a labelled row of report_utilization
proc util_used {txt needle} {
    foreach line [split $txt "\n"] {
        if {[string first $needle $line] >= 0} {
            if {[regexp {\|\s*([0-9]+)\s*\|} $line -> v]} { return $v }
        }
    }
    return 0
}
proc cell_cnt {ref} { return [llength [get_cells -hierarchical -quiet -filter "REF_NAME == $ref"]] }
proc emit_res {dat label val} { if {$val > 0} { puts $dat "RES|$label|$val" } }

# ---- resource rows (only counts > 0) ---------------------------------------
emit_res $dat "Slice LUTs (total)"         [util_used $util_txt "Slice LUTs"]
emit_res $dat "  - LUT as logic"           [util_used $util_txt "LUT as Logic"]
emit_res $dat "  - LUT as memory (SRL16E)" [util_used $util_txt "LUT as Memory"]
emit_res $dat "Slice registers (FF)"       [util_used $util_txt "Slice Registers"]
emit_res $dat "CARRY4"                      [cell_cnt CARRY4]
emit_res $dat "F7 muxes (MUXF7)"           [cell_cnt MUXF7]
emit_res $dat "F8 muxes (MUXF8)"           [cell_cnt MUXF8]
emit_res $dat "DSP (DSP48E1)"              [cell_cnt DSP48E1]
emit_res $dat "Block RAM (RAMB36E1)"       [cell_cnt RAMB36E1]
emit_res $dat "Block RAM (RAMB18E1)"       [cell_cnt RAMB18E1]
emit_res $dat "SRL16E"                      [cell_cnt SRL16E]

# ---- critical path (worst reg->reg) + Fmax (period = 10 ns) -----------------
set period 10.0
set cp [get_timing_paths -delay_type max -max_paths 1 -nworst 1 -quiet]
if {[llength $cp]} {
    set slack [get_property SLACK $cp]
    set fmax  [expr {1000.0 / ($period - $slack)}]
    puts $dat "FMAX|[format %.1f $fmax]|[format %.3f $slack]|[format %.1f $period]"
    puts $dat "CPATH|delay|[format %.3f [get_property DATAPATH_DELAY $cp]]|[get_property LOGIC_LEVELS $cp]"
    puts $dat "CPATH|start|[get_property STARTPOINT_PIN $cp]"
    puts $dat "CPATH|end|[get_property ENDPOINT_PIN $cp]"
}

# ---- per-top-level-signal I/O delay (ports timed at 0 external delay) -------
set in_ports  [get_ports -filter {DIRECTION == IN  && NAME != "f_clk"}]
set out_ports [get_ports -filter {DIRECTION == OUT}]
set_input_delay  0 -clock f_clk $in_ports
set_output_delay 0 -clock f_clk $out_ports

# group bus bits under their base name, preserving declaration order
proc group_ports {ports} {
    set g [dict create]
    foreach p $ports {
        regsub {\[.*\]} [get_property NAME $p] {} b
        dict lappend g $b $p
    }
    return $g
}
set ig [group_ports $in_ports]
foreach b [dict keys $ig] {
    set pth [get_timing_paths -from [dict get $ig $b] -to [all_registers] -delay_type max -max_paths 1 -nworst 1 -quiet]
    if {[llength $pth]} {
        puts $dat "IOIN|$b|[format %.3f [get_property DATAPATH_DELAY $pth]]|[get_property LOGIC_LEVELS $pth]"
    } else { puts $dat "IOIN|$b|n/a|-" }
}
set og [group_ports $out_ports]
foreach b [dict keys $og] {
    set pth [get_timing_paths -from [all_registers] -to [dict get $og $b] -delay_type max -max_paths 1 -nworst 1 -quiet]
    if {[llength $pth]} {
        puts $dat "IOOUT|$b|[format %.3f [get_property DATAPATH_DELAY $pth]]|[get_property LOGIC_LEVELS $pth]"
    } else { puts $dat "IOOUT|$b|n/a|-" }
}
# combinational input->output feed-through (present only with REG_IO = 0)
set ff [get_timing_paths -from $in_ports -to $out_ports -delay_type max -max_paths 1 -nworst 1 -quiet]
if {[llength $ff]} {
    puts $dat "IOFF|input->output (comb)|[format %.3f [get_property DATAPATH_DELAY $ff]]|[get_property LOGIC_LEVELS $ff]"
}
close $dat

puts "==== SYNTH DONE ===="
puts "Reports in: $OUT_DIR"
