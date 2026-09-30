# SHARMONY

SHARMONY is a unified hardware hash accelerator for the SHA-2, SHA-3, SHAKE, and cSHAKE families. The design combines the supported algorithms in a shared 64-bit datapath and also supports dual SHA-224/SHA-256 duet execution.

📄 The full interface, microarchitecture, and configuration reference is in the [SHARMONY Hardware Specification](docs/sharmony_hw_spec.pdf).

## Key features

- Unified RTL implementation for SHA-2, SHA-3, SHAKE, and cSHAKE.
- Shared 64-bit datapath architecture.
- Customizable XOF support via cSHAKE128/cSHAKE256 (NIST SP 800-185): the core applies the cSHAKE domain separation and SHAKE rate/capacity; the function-name (`N`) and customization (`S`) strings are supplied by the host as the standard `bytepad`-encoded preamble streamed ahead of the message.
- Support for dual SHA-224/SHA-256 duet execution.
- Context switching (`state_save`/`state_load`): export and re-import the internal hash state for resumable hashing — SHA-2 (8-word chaining value) and SHA-3 (full 25-lane Keccak state). Building block for suspended/interleaved contexts and keyed constructions (HMAC, KMAC).
- Mid-state caching (`state_cache`): retain a computed prefix state in an on-chip single-slot register and reuse it across many message hashes with no bus transfer — fixed-prefix reuse for PQC (SLH-DSA, XMSS).
- Streaming input interface with ready/valid back-pressure.
- Streaming digest/XOF output interface with ready/valid back-pressure.
- Verification using NIST CAVP test vectors.
- Zeroization input for clearing internal state (all sensitive registers are scrubbed within the zeroize window).
- Synchronous active-low reset (`resetn`); every flip-flop uses synchronous reset.

## Getting started

Let's get started! The section goes from a clean checkout to a first passing test in 3 steps: the tool requirements per flow, their installation, and a quick check that runs the build and a first test.

### Requirements

Only Verilator, Make and a C++ compiler are required to build and run the tests; Vivado and yosys are needed only for the optional synthesis flows.

| Flow | Tools | Notes |
|---|---|---|
| Simulation and tests (`make build`, `make run-<TESTNAME>`) | Verilator 5.x, GNU Make, a C++17 compiler (g++ or clang++) | Tested with Verilator 5.050. |
| Waveforms (optional) | any VCD viewer: GTKWave, [Surfer](https://surfer-project.org) | `make run-<TESTNAME> VCD=1` writes `tb/work/vcd/<TESTNAME>.vcd`; `make vcd-<TESTNAME>` opens Surfer on it. |
| FPGA synthesis (`make synth-vivado`, optional) | AMD Vivado | The figures in this README were produced with Vivado 2025.2. |
| ASIC synthesis (`make synth-yosys`, optional) | yosys with the slang SystemVerilog frontend; the Nangate 45 nm Open Cell Library liberty file | The liberty file is **not bundled** (its license differs from this repository's Apache-2.0); it is in the [OpenROAD-flow-scripts](https://github.com/The-OpenROAD-Project/OpenROAD-flow-scripts) repository under `flow/platforms/nangate45/lib/`. |

### Installing

Everything but Vivado comes in one archive: an [OSS CAD Suite](https://github.com/YosysHQ/oss-cad-suite-build) release contains Verilator 5.x, yosys with slang, GTKWave and Surfer, prebuilt. Download a release from its releases page and unpack it:

```bash
tar xzf oss-cad-suite-linux-x64-<YYYYMMDD>.tgz
export PATH="$PWD/oss-cad-suite/bin:$PATH"
verilator --version        # Verilator 5.0xx
```

Where the archive is not wanted, a distribution package of Verilator 5.x (`verilator --version` shows the version) or a build from source per Verilator's installation guide works as well.

The liberty file for the ASIC flow:

```bash
git clone --depth 1 https://github.com/The-OpenROAD-Project/OpenROAD-flow-scripts
cp OpenROAD-flow-scripts/flow/platforms/nangate45/lib/NangateOpenCellLibrary_typical.lib synth/lib/
```

Tool locations are Make variables, so nothing has to be on `PATH`: `VERILATOR=/path/to/verilator`, `YOSYS_BIN=/path/to/yosys`, `VIVADO_BIN=/path/to/vivado`, `NANGATE_LIB=/path/to/NangateOpenCellLibrary_typical.lib`, each given on the `make` command line.

### Quick check

From the repository root (the directory with the `Makefile`):

```bash
make build                    # Verilator build of the testbench: one binary, every test
make list-tests               # the registered tests
make run-sha256_shortmsg      # one NIST CAVP test: PASS / FAIL and the log in tb/work/logs/sha256_shortmsg/log
make run-performance          # cycle counts and throughput of every mode
```

A test prints its verdict and the counts by default; `VERBOSE=1` adds one line per vector, `VERBOSE=2` the messages, digests and output beats as well (see *Tests* below). `make` alone prints the help with every target and option (`REG_IO`, `VCD`, `VERBOSE`, `MAX_VECTORS`, `RSP`, `FREQ_MHZ`). The tests, how they are built and how to add one are described in [tb/README.md](tb/README.md); the synthesis flows and the numbers they reproduce in *Results* below.


## Hardware (RTL)


The RTL is located in `hw/sharmony/`, with `essec_sharmony_top` as the top-level module. The signal table, the operation sequence, the state-pin matrix, the mode table and the configuration parameters with their cost are in [hw/sharmony/README.md](hw/sharmony/README.md).

## Testbench

The testbench is located in `tb/`: a Verilator/C++ flow whose single binary (`make build`) runs every registered test against the NIST vectors (CAVP SHAVS for SHA-2, CAVP SHA3VS for SHA-3 and SHAKE, the SP 800-185 samples for cSHAKE) plus the interface, error, zeroize, midstate and performance scenarios. The tests, the run options and the output, and how to add a test are described in [tb/README.md](tb/README.md).

## Results 

Every number in this section comes out of one `make` target of this repository; the target is named with each table.

### FPGA resource utilization and timing

The target runs `vivado` from `PATH` (the Makefile is generic, `VIVADO_BIN ?= vivado`): add the Vivado binary directory first, `export PATH=/opt/Xilinx/2025.2/Vivado/bin:$PATH`, or name the binary on the command line, `make synth-vivado VIVADO_BIN=/opt/Xilinx/2025.2/Vivado/bin/vivado`.

`make synth-vivado REG_IO=1` and `make synth-vivado REG_IO=0`: Vivado out-of-context synthesis of `essec_sharmony_top` for `xc7a200tfbg484-3` (Artix-7, speed grade −3) with a 10 ns clock constraint and the default synthesis directive (`synth/sharmony_top/synth.tcl`). The target prints the tables below and leaves `utilization.rpt`, `timing_summary.rpt` and `report.dat` in `synth/work/`. Figures are for the default configuration (`ROM_USE_BRAM = 1`); `ROM_USE_BRAM = 0` removes the block RAM and adds ~310 LUTs / 65 FFs.

| Resource | `REG_IO = 1` (registered, default) | `REG_IO = 0` (combinational) |
|---|---:|---:|
| Slice LUTs (total) | 5873 | 6044 |
| &nbsp;&nbsp;— LUT as logic | 5745 | 5916 |
| &nbsp;&nbsp;— LUT as memory (SRL16E) | 128 | 128 |
| Slice registers (FF, all FDRE) | 2310 | 2039 |
| CARRY4 | 254 | 254 |
| Block RAM (RAMB36E1) | 1 | 1 |
| DSP slices | 0 | 0 |

| Characteristic | `REG_IO = 1` (registered) | `REG_IO = 0` (combinational) |
|---|---:|---:|
| Internal Fmax (register-to-register, SHA-2 round path) | 132 MHz | 132 MHz |
| Worst input port → first flip-flop | ~2.5 ns (2 levels, `resetn`) | ~5.8 ns (deep `byte_len` count path) |
| Worst last flip-flop → output port (clock-to-out) | ~1.0 ns (0 levels) | ~5.4 ns (`output_data`) |
| Combinational input → output path | none | present |
| I/O latency overhead (start → first output) | +3 cycles | none |

The I/O ports carry no input/output-delay constraints, so the delays above are the measured worst-case combinational path delays at the boundary, and the internal Fmax reflects the register-to-register critical path (the SHA-2 round chain: the Σ1/Ch/adder path updating E), which is identical for both configurations. With `REG_IO = 1` every data port presents at logic depth 0 except `output_ready` (1 level), `zeroize` and `resetn` (2 levels), and `start` and `input_valid`/`input_final` (3 levels, the back-pressure decode); the control input `mode` is directly registered (depth 0) in **both** configurations; `state_load`, `state_save`, and `state_cache` see one LUT level (~0.8 ns) — the resume-wins guard `state_save && !(state_load && state_cache)` in front of the `state_save` latch. All flip-flops use synchronous reset and map to the FDRE primitive. `output_data` is driven to zero whenever `output_valid` is low. Neither configuration uses DSP slices.

### ASIC area (gate equivalents)

The target runs `yosys` from `PATH` (`YOSYS_BIN ?= yosys`) and reads the liberty file from `synth/lib/` (`NANGATE_LIB`): add the OSS CAD Suite binary directory first, `export PATH=$PWD/oss-cad-suite/bin:$PATH`, or name both on the command line, `make synth-yosys YOSYS_BIN=/path/to/oss-cad-suite/bin/yosys NANGATE_LIB=/path/to/NangateOpenCellLibrary_typical.lib`.

`make synth-yosys REG_IO=1` and `make synth-yosys REG_IO=0`: technology-independent area from an open-source ASIC mapping, yosys with the slang SystemVerilog frontend, mapped to the Nangate 45 nm Open Cell Library (`typical` corner) with module boundaries preserved. For a fabric-neutral result the design is synthesized in its generic configuration — `ADDER_IMPL = ADDER_GENERIC` (no Xilinx `CARRY4`) and `ROM_USE_BRAM = 0` (round-constants ROM as standard-cell logic); the target sets both for the run and restores the package afterwards. One gate equivalent (GE) is the area of a 2-input NAND (`NAND2_X1`, 0.798 µm²). This is an unconstrained area metric (no clock/timing constraints), so absolute counts differ from the Artix-7 LUT/FF figures above, and they move by a few percent between yosys releases (its optimization passes change from release to release).

| Component | `REG_IO = 1` (kGE) | `REG_IO = 0` (kGE) |
|---|---:|---:|
| Hash core — control + datapath (excl. SHA-2 adders) | 45.9 | 43.8 |
| SHA-2 round adders (13 dual-mode, 64-bit or 2×32-bit) | 6.3 | 6.3 |
| Padding front-end (`essec_sharmony_pad`) | 3.2 | 2.5 |
| Round-constants ROM (distributed) | 1.7 | 1.7 |
| Top-level I/O glue | 0.1 | 0.1 |
| **Total** | **57.2** | **54.4** |

Produced with yosys 0.67 (OSS CAD Suite release 2026-08-02) on the RTL of this repository. The mapping is heuristic and unconstrained, so another yosys release lands a few percent away: yosys 0.54 gives 59.3 / 56.8 kGE for the same design.

### Latency and throughput

`make run-performance` (the default `REG_IO = 1`, `FREQ_MHZ=132`, the internal Fmax above): cycle-accurate latency and throughput of every mode from simulation. The `REG_IO = 0` column below comes from the same test after setting `REG_IO_DEFAULT` to `1'b0` in `hw/sharmony/essec_sharmony_pkg.sv` and rebuilding (`make build`); the simulation takes the boundary from the package, not from the command line. Cycles are edge-counted.

Single-block hash (SHA-224, one 512-bit block):

| Latency | `REG_IO = 1` | `REG_IO = 0` |
|---|---:|---:|
| start → first `output_valid` | 68 cycles | 65 cycles |
| start → `busy` deasserted | 73 cycles | 72 cycles |

The **end-to-end latency** (start → `busy` deasserted, **73** for `REG_IO = 1`) is the performance test's `end-to-end (start->done)` metric and the SHA-224 row below. The registered I/O boundary adds **+3 cycles** to the host-visible start→first-output latency (≈1 input + 2 output register stages) versus the combinational one. Latency scales with message length by the per-block cost: an *N*-block message takes `Fixed + N × Per-block` cycles.

Per mode, at `f_clk = 132 MHz`. *1-block latency* is the edge-counted end-to-end time (external `start` asserted → `busy` deasserted) for a single-block message; *Per-block* is the steady-state cost of one additional compression/permutation block; *Throughput* is the long-message rate `8 × rate_bytes × f_clk / Per-block`:

| Mode | Block [B] | Digest [bit] | 1-block latency [cyc] | Per-block [cyc] | Throughput [Mbit/s] |
|---|---:|---:|---:|---:|---:|
| SHA-224 | 64 | 224 | 73 | 69 | 979 |
| SHA-256 | 64 | 256 | 73 | 69 | 979 |
| SHA-224 / SHA-256 — duet (2-lane) | 128 | 224 / 256 | 73 | 69 | 1959 |
| SHA-384 | 128 | 384 | 89 | 85 | 1590 |
| SHA-512 | 128 | 512 | 89 | 85 | 1590 |
| SHA-512/224 | 128 | 224 | 89 | 85 | 1590 |
| SHA-512/256 | 128 | 256 | 89 | 85 | 1590 |
| SHA3-224 | 144 | 224 | 52 | 42 | 3621 |
| SHA3-256 | 136 | 256 | 51 | 41 | 3503 |
| SHA3-384 | 104 | 384 | 49 | 37 | 2968 |
| SHA3-512 | 72 | 512 | 47 | 33 | 2304 |
| SHAKE128 | 168 | XOF | 55 | 45 | 3942 |
| SHAKE256 | 136 | XOF | 51 | 41 | 3503 |

**Duet** runs SHA-224/256 as two independent 32-bit lanes in lockstep: identical cycle count, double the throughput (128-byte block-pair vs 64-byte single lane). **SHAKE** rows are extendable-output (XOF); the throughput shown is the absorb/squeeze rate and scales with the requested output length. Throughput scales linearly with `f_clk`: `FREQ_MHZ=<MHz>` on the command line recomputes the last column for another clock. Full per-mode cycle-phase breakdowns (`Fixed = Lead + Init + Tail − Gap`, `Per-block = Rounds + Absorb + Gap`) are printed by the test (`VERBOSE=1` adds the FSM-state detail).

## Repository structure

```text
SHARMONY/
├── docs/
│   ├── figures/                   # block diagrams and figures
│   ├── waveforms/                 # rendered timing-diagram figures (PDF)
│   └── sharmony_hw_spec.pdf       # hardware specification document
├── hw/
│   └── sharmony/                  # SHARMONY RTL source files
│       ├── README.md              # the configuration parameters, their cost, how to pick them
│       ├── essec_sharmony_*.sv    # pkg, top, core, pad, rom, adders (add32_32 / add32_c4 / add32_c8 / add4_c4 / add8_c8)
│       └── CARRY4.v, CARRY8.v, MUXCY.v  # Xilinx carry-primitive sim models (Apache-2.0, see file headers)
├── synth/                         # out-of-context synthesis flows (Vivado / yosys)
│   ├── sharmony_top/              # SHARMONY core OOC synth (make synth-vivado)
│   ├── lib/                       # Nangate45 liberty goes here (not bundled, see Requirements)
│   ├── work/                      # generated reports / checkpoints — gitignored
│   ├── ge_table.awk               # builds the ASIC gate-equivalent (kGE) area table
│   └── vivado_tables.awk          # formats Vivado resource/timing/I-O tables
├── tb/
│   ├── README.md                  # the tests: what they check, how to run them, how to add one
│   ├── src/                       # Verilator/C++ simulation flow
│   │   ├── sharmony_verilator_wrapper.sv
│   │   ├── main.cpp
│   │   ├── SharmonyDriver.{cpp,hpp}
│   │   ├── TestRegistry.{cpp,hpp}
│   │   ├── RspParser.{cpp,hpp}
│   │   └── tests/
│   │       ├── common/            # shared C++ test utilities
│   │       ├── data/*.rsp         # NIST CAVP response vectors
│   │       └── *_test.cpp         # registered test scenarios
│   └── work/                      # generated build, log, VCD, and report output — gitignored
├── LICENSE                        # Apache License, Version 2.0
├── Makefile                       # build, lint, test, waveform, synthesis and clean targets
└── README.md
```


## Publication

```bibtex
@article{Anwar2026Sharmony, 
    author  = {Liga Anwar and Carlos Andres Lara-Nino and Jong-Yeon Park and Michael Hutter},
    title   = {{SHARMONY}: Composing {SHA}-2 and {SHA}-3 Hardware for Crypto-Agile {PQC}},
    journal = {IACR Transactions on Cryptographic Hardware and Embedded Systems},
    volume  = {2026},
    number  = {4},
    pages   = {945--969},
    year    = {2026},
    doi     = {10.46586/tches.v2026.i4.945-969},
    url     = {https://tches.iacr.org/index.php/TCHES/article/view/13266}
}
```

## Acknowledgement

This work has received funding from the EU’s Horizon Europe research and innovation programme under grant agreement No. 101225722 (FORTRESS)

## License / copyright

Copyright © 2025-2026 Universität der Bundeswehr München / Research Institute CODE - ESSEC Lab.

Lab-authored code is licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE) and the SPDX headers in each file. The Xilinx carry-primitive simulation models (`hw/sharmony/CARRY4.v`, `CARRY8.v`, `MUXCY.v`) are Xilinx-copyrighted and Apache-2.0-licensed (see their file headers). The Nangate 45 nm Open Cell Library used by the optional ASIC synthesis flow is not bundled; it is downloaded separately under its own license (see Requirements).
