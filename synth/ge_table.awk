# /////////////////////////////////////////////////////////////////////////////////////
# //
# // Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
# // Licensed under the Apache License, Version 2.0, see LICENSE for details.
# // SPDX-License-Identifier: Apache-2.0
# //
# /////////////////////////////////////////////////////////////////////////////////////
# //
# // Aggregate Nangate-mapped per-module areas (from one yosys `stat -liberty`
# // output) into a per-component gate-equivalent (kGE) table.
# // Usage: awk -v n2=<NAND2_area_um2> -v rio=<0|1> -f ge_table.awk stat.txt
# //
# // Module names from the hierarchy-preserving (--best-effort-hierarchy) flow are
# // uniquified as  <type>$essec_sharmony_top.<instance> ; the top module itself is
# // the only "Chip area for module" line without a '$'. The "Chip area for top
# // module" grand-total line is intentionally NOT matched (no "for module").
# //
# /////////////////////////////////////////////////////////////////////////////////////

function kge(x)      { return x / n2 / 1000 }
function row(lbl, k) { printf "  %-42s %10.1f\n", lbl, kge(A[k]) }

/Chip area for module/ {
    a = $NF
    if      ($0 !~ /\$/)                 b = "top"
    else if ($0 ~ /add32_32/)            b = "add"
    else if ($0 ~ /essec_sharmony_core/) b = "core"
    else if ($0 ~ /essec_sharmony_pad/)  b = "pad"
    else if ($0 ~ /essec_sharmony_rom/)  b = "rom"
    else                                 b = "other"
    A[b] += a
    T    += a
}

END {
    printf "  Per-component area in kGE  (1 GE = %.3f um^2)\n\n", n2
    printf "  %-42s %10s\n", "Component", "REG_IO=" rio
    printf "  %-42s %10s\n", "------------------------------------------", "----------"
    row("Hash core (ctrl+datapath, excl. adders)", "core")
    row("SHA-2 round adders (13 dual-mode 64/2x32)", "add")
    row("Padding front-end",                       "pad")
    row("Round-constants ROM (distributed)",       "rom")
    row("Top-level I/O glue",                      "top")
    printf "  %-42s %10s\n", "------------------------------------------", "----------"
    printf "  %-42s %10.1f\n", "TOTAL", kge(T)
}
