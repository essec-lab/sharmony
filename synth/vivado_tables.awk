# /////////////////////////////////////////////////////////////////////////////////////
# //
# // Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
# // Licensed under the Apache License, Version 2.0, see LICENSE for details.
# // SPDX-License-Identifier: Apache-2.0
# //
# /////////////////////////////////////////////////////////////////////////////////////
# //
# // Format the Vivado-flow resource / timing / I/O-delay tables from the tagged
# // data file written by synth/sharmony_top/synth.tcl (synth/work/report.dat).
# // Usage: awk -f vivado_tables.awk report.dat
# //
# // Tagged input lines:
# //   RES|<label>|<used>
# //   FMAX|<MHz>|<wns_ns>|<period_ns>
# //   CPATH|delay|<ns>|<levels>   CPATH|start|<pin>   CPATH|end|<pin>
# //   IOIN|<signal>|<ns>|<levels>     IOOUT|<signal>|<ns>|<levels>
# //   IOFF|<label>|<ns>|<levels>      (combinational input->output, REG_IO=0 only)
# //
# /////////////////////////////////////////////////////////////////////////////////////

BEGIN { FS = "|" }

/^RES\|/          { rn[++nr] = $2; rv[nr] = $3 }
/^FMAX\|/         { fmax = $2; wns = $3; per = $4 }
/^CPATH\|delay\|/ { cpd = $3; cpl = $4 }
/^CPATH\|start\|/ { cps = $3 }
/^CPATH\|end\|/   { cpe = $3 }
/^IOIN\|/         { in_n[++ni] = $2; in_d[ni] = $3; in_l[ni] = $4 }
/^IOOUT\|/        { on_n[++no] = $2; on_d[no] = $3; on_l[no] = $4 }
/^IOFF\|/         { ff_n = $2; ff_d = $3; ff_l = $4 }

END {
    print  "  FPGA resource utilization"
    printf "  %-28s %8s\n", "Resource", "Used"
    printf "  %-28s %8s\n", "----------------------------", "--------"
    for (i = 1; i <= nr; i++) printf "  %-28s %8s\n", rn[i], rv[i]

    print  ""
    printf "  Timing  (clock period %s ns)\n", per
    printf "    Max frequency : %s MHz   (WNS %s ns)\n", fmax, wns
    printf "    Critical path : %s ns over %s logic levels (worst reg -> reg)\n", cpd, cpl
    printf "      from : %s\n", cps
    printf "      to   : %s\n", cpe

    print  ""
    print  "  Top-level I/O delay (ns)  [unconstrained ports, 0 external delay]"
    printf "  %-22s %-5s %9s %7s\n", "Signal", "Dir", "Delay", "Levels"
    printf "  %-22s %-5s %9s %7s\n", "----------------------", "-----", "---------", "-------"
    for (i = 1; i <= ni; i++) printf "  %-22s %-5s %9s %7s\n", in_n[i], "in",  in_d[i], in_l[i]
    for (i = 1; i <= no; i++) printf "  %-22s %-5s %9s %7s\n", on_n[i], "out", on_d[i], on_l[i]
    if (ff_n != "") printf "  %-22s %-5s %9s %7s\n", ff_n, "i->o", ff_d, ff_l
}
