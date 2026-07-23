# SHARMONY

SHARMONY is a unified hardware hash accelerator for the SHA-2, SHA-3, SHAKE, and cSHAKE families. The design combines the supported algorithms in a shared 64-bit datapath and also supports dual SHA-224/SHA-256 duet execution.

📄 The full interface, microarchitecture, and configuration reference is in the [SHARMONY Hardware Specification](docs/sharmony_hw_spec.pdf).

## Publication

```bibtex
@InProceedings{Anwar26Sharmony,
  author        = {Liga Anwar and Carlos Andres Lara-Nino and Jong-Yeon Park and Michael Hutter},
  title         = {{SHARMONY}: Composing {SHA}-2 and {SHA}-3 Hardware for Crypto-Agile {PQC}},
  booktitle     = {IACR Transactions on Cryptographic Hardware and Embedded Systems (TCHES),
                  2026(4), Antalya, Turkey, October 11-15, 2026, Proceedings},
  pages         = {to appear},
  year          = {2026}
}
```

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

## Supported modes

The top-level mode input uses the `mode_e` enumeration from `essec_sharmony_pkg.sv`.

| Family | Variant | RTL identifier | Mode value | Digest/Output size | SHA-3/SHAKE rate | SHA-3/SHAKE capacity |
|---|---|---:|---:|---:|---:|---:|
| SHA-2 | SHA-224 | `HASH_SHA2_224` | `4'h0` | 224 bit | - | - |
| SHA-2 | SHA-256 | `HASH_SHA2_256` | `4'h1` | 256 bit | - | - |
| SHA-2 | SHA-384 | `HASH_SHA2_384` | `4'h2` | 384 bit | - | - |
| SHA-2 | SHA-512 | `HASH_SHA2_512` | `4'h3` | 512 bit | - | - |
| SHA-2 | SHA-512/224 | `HASH_SHA2_512_224` | `4'h4` | 224 bit | - | - |
| SHA-2 | SHA-512/256 | `HASH_SHA2_512_256` | `4'h5` | 256 bit | - | - |
| SHA-3 | SHA3-224 | `HASH_SHA3_224` | `4'h6` | 224 bit | 1152 bit | 448 bit |
| SHA-3 | SHA3-256 | `HASH_SHA3_256` | `4'h7` | 256 bit | 1088 bit | 512 bit |
| SHA-3 | SHA3-384 | `HASH_SHA3_384` | `4'h8` | 384 bit | 832 bit | 768 bit |
| SHA-3 | SHA3-512 | `HASH_SHA3_512` | `4'h9` | 512 bit | 576 bit | 1024 bit |
| SHAKE | SHAKE128 | `XOF_SHAKE128` | `4'hA` | arbitrary | 1344 bit | 256 bit |
| SHAKE | SHAKE256 | `XOF_SHAKE256` | `4'hB` | arbitrary | 1088 bit | 512 bit |
| cSHAKE | cSHAKE128 | `XOF_CSHAKE128` | `4'hC` | arbitrary | 1344 bit | 256 bit |
| cSHAKE | cSHAKE256 | `XOF_CSHAKE256` | `4'hD` | arbitrary | 1088 bit | 512 bit |

cSHAKE128/cSHAKE256 (NIST SP 800-185) reuse the SHAKE128/SHAKE256 rate and capacity but apply the cSHAKE domain suffix (`0x04`) instead of the plain SHAKE suffix (`0x1F`). The customization is realized at the interface: the host prepends the SP 800-185 `bytepad(encode_string(N) ‖ encode_string(S), rate)` preamble — the function-name string `N` and customization string `S` — to the message stream; the core hashes it as a single absorbed input. (Per SP 800-185, an empty `N` and `S` is defined to fall back to plain SHAKE; if that fallback is required, select the corresponding `XOF_SHAKE*` mode.)

## Top-level RTL interface

The main integration wrapper is `essec_sharmony_top`. It instantiates the padding front end and the shared hash core, and exposes a streaming message input together with a streaming digest/XOF output.

### Top-level signals

| Signal | Direction | Width | Description |
|---|---:|---:|---|
| `f_clk` | Input | 1 | Clock input. All state updates occur on the rising edge of this clock. |
| `resetn` | Input | 1 | Synchronous active-low reset. Hold low for at least one clock cycle to reset the padder, core, counters, and internal control state. All flip-flops use synchronous reset (sampled on the rising edge of `f_clk`). |
| `start` | Input | 1 | Starts a new hash/XOF operation. Assert when `busy` is low and keep `mode` stable for the selected operation. A one-cycle pulse is sufficient. |
| `zeroize` | Input | 1 | Requests zeroization of internal state. While zeroization is active, the input stream is not accepted and `busy` stays high. |
| `mode` | Input | `mode_e` / 4 | Selects the hash/XOF algorithm. Use one of the valid `mode_e` values listed in the supported modes table. |
| `busy` | Output | 1 | Busy status. High while a hash/XOF operation or zeroization is in progress (padder or core non-idle). A new `start` is accepted only when `busy` is low. |
| `state_load` | Input | 1 | Context switching. When high at `start`, the operation resumes from a loaded state: the first N input beats are the saved mid-state (SHA-2: 8 beats; SHA-3: 25 beats) and replace the IV / zeroed sponge. Sampled with `start` and held for the operation. |
| `state_save` | Input | 1 | Context switching. When high at `start`, the terminal beat (`input_final`) exports the full un-padded internal state (SHA-2: 8-word chaining value; SHA-3: 25-lane Keccak state) instead of the padded digest. Requires block-aligned input. Sampled with `start`. |
| `state_cache` | Input | 1 | On-chip mid-state fast path (SHA-2). When high at `start` together with `state_save`/`state_load`, the mid-state is kept in / resumed from an internal single-slot register instead of being streamed over the message bus — no export beats on save, no re-streamed state beats on load. Lets a fixed prefix be computed once and reused across many message hashes without the off-chip round-trip. Sampled with `start`. |
| `input_data` | Input | 64 | Message input beat. Data is accepted only when `input_valid && input_ready` is high. |
| `input_valid` | Input | 1 | Qualifies `input_data`, `input_bytes`, and `input_final` on the message input stream. |
| `input_bytes` | Input | 6 | Number of valid message bytes in the current input beat. For normal 64-bit streaming modes, use values from 0 to 8. For SHA-224/SHA-256 duet operation, the field is split into two 3-bit byte counts: `[5:3]` for the upper 32-bit lane and `[2:0]` for the lower 32-bit lane. |
| `input_final` | Input | 2 | Marks the final input beat. For solo execution modes, any nonzero value marks the beat as final (the two bits are equivalent; driving `2'b11` is recommended for symmetry with duet mode). For SHA-224/SHA-256 duet execution, bit 1 marks the upper 32-bit lane as final and bit 0 marks the lower 32-bit lane as final; the two lanes may finalize on different beats. |
| `input_ready` | Output | 1 | Message stream back-pressure signal. The wrapper accepts an input beat only when this signal is high together with `input_valid`. |
| `output_data` | Output | 64 | Digest or XOF output beat. The value is valid when `output_valid` is high. **Note:** SHA-2 fixed-length digests are streamed in **reverse word order** (most-significant word first); SHA-3/SHAKE stream in forward order. See the output word-order note under *Operation sequence*. |
| `output_valid` | Output | 1 | Qualifies `output_data`. For fixed-length hash modes, output words are consumed when `output_valid && output_ready` is high. |
| `output_ready` | Input | 1 | Output consumer ready signal. For fixed-length hash modes, assert to consume digest words. For SHAKE modes, keeping this signal high continues XOF squeezing; deassert it to stop the XOF output stream. |

### Operation sequence

1. Apply reset by holding `resetn` low for at least one clock cycle (reset is synchronous — sampled on the rising edge of `f_clk`), then release it high.
2. Wait until `busy` is low.
3. Drive the desired `mode` and pulse `start` high for one clock cycle.
4. Send message beats using the input ready/valid handshake:
   - A beat is accepted when `input_valid && input_ready` is high.
   - Use `input_bytes` to indicate the number of valid bytes in the beat.
   - Mark the last beat with `input_final`.
5. Read digest or XOF output beats using the output ready/valid handshake:
   - A fixed-length digest beat is consumed when `output_valid && output_ready` is high.
   - For SHAKE modes, keep `output_ready` asserted for as many 64-bit output beats as required, then deassert it to terminate squeezing.
   - **Output word order.** SHA-2 fixed-length digests are emitted in **reverse word order** — the highest-index digest word first, down to `H0` (e.g. `H7, H6, …, H0` for SHA-512/256; `H6 … H0` for SHA-224; `H5 … H0` for SHA-384; `H3 … H0` for SHA-512/224 & SHA-512/256). Each individual word is still in big-endian byte order. This lets the core stream the early-finalized words out during the last accumulation cycles (saving up to 4 output cycles). **SHA-3 and SHAKE are unaffected and stream in forward order (`H0` first).** A consumer must therefore reverse the SHA-2 word sequence to reconstruct the standard digest; back-pressure (`output_ready` low) is honored for every beat, including the overlapped ones.
6. Wait for `busy` to return low before starting the next operation.

### State Management (`state_load` / `state_save` / `state_cache`)

`state_load`, `state_save`, and `state_cache` are sampled with `start` and qualify how an operation begins and ends. They serve two complementary use models:

- **Context switching** (`state_save` / `state_load`) — export the un-padded internal state and re-import it later, so a hash context can be suspended and resumed (or interleaved with others). This is the building block for SHA context switches and higher-level keyed constructions such as **HMAC** and **KMAC**.
- **Mid-state caching** (`state_cache`) — retain a computed prefix state in an on-chip single-slot register and reuse it across many message hashes with no bus transfer. Primarily targets fixed-prefix **PQC** hashing (SLH-DSA, XMSS).

The full pin matrix:

| `state_cache` | `state_load` | `state_save` | Operation | Starts from | On the terminal beat (`input_final`) |
|:---:|:---:|:---:|---|---|---|
| 0 | 0 | 0 | Normal hash | IV / zeroed state | pad → emit digest |
| 0 | 0 | 1 | Compute + save | IV / zeroed state | no pad → export mid-state |
| 0 | 1 | 0 | Resume + finalize | streamed mid-state | pad → emit digest |
| 0 | 1 | 1 | Resume + save | streamed mid-state | no pad → export mid-state |
| 1 | 0 | 0 | Normal hash (`state_cache` alone has no effect) | IV / zeroed state | pad → emit digest |
| 1 | 0 | 1 | **Cache-save** (SHA-2 only) | IV / zeroed state | no pad → state retained on-chip, **no beats emitted** |
| 1 | 1 | 0 | **Cache-resume + finalize** (SHA-2 only) | on-chip cache slot (no state beats streamed) | pad → emit digest |
| 1 | 1 | 1 | Behaves as **cache-resume + finalize**: `state_save` is ignored (resume wins, dropped at the control latch) | on-chip cache slot | pad → emit digest |

`state_cache` is meaningful for SHA-2 modes only (the slot holds a SHA-2 chaining value); in SHA-3/SHAKE modes it must be held low — those modes save/resume exclusively through the streamed flow.

#### Context switching (`state_save` / `state_load`)

The streamed flow (`state_cache` low) moves the internal state in and out over the 64-bit message bus.

- **Mid-state size:** SHA-2 = 8 × 64-bit beats (the chaining value `H`; SHA-256/224 use the low 32 bits of each lane); SHA-3/SHAKE = 25 × 64-bit beats (the full Keccak state).
- **Load:** with `state_load`, stream the N mid-state beats first — in the same order/format `state_save` produced — then the message.
- **Save:** requires block-aligned input (no padding is appended); the exported state re-imports byte-for-byte via `state_load`.
- **Resume + finalize** assumes a single-block prefix for the SHA-2 length field, so the appended length is the *total* (prefix + resumed) message.
- Because it moves the full state, this path covers every mode — including SHA-3/SHAKE — and underpins HMAC/KMAC and other resumable, context-switched hashing.

#### Mid-state caching (`state_cache`)

`state_cache` keeps the mid-state in an internal single-slot register instead of streaming it over the message bus, eliminating the transfer entirely (SHA-2):

- **Cache-save** (`state_cache & state_save`): the block-aligned prefix is absorbed and its chaining value is retained on-chip; no mid-state beats are emitted.
- **Cache-resume** (`state_cache & state_load`): the operation starts directly from the cached chaining value — the 8 state beats are *not* re-streamed — then the message tail (any length, including multi-block) is appended and finalized. A resume does **not** consume the slot: after the digest, the slot holds the chaining value at the **last full-block boundary** of the resumed stream. A sub-block tail therefore leaves it unchanged (the basis for repeated resumes from the same cached prefix), while a block-aligned message advances it by those blocks.
- **Resume + save together** (`state_cache & state_load & state_save`): the save request is **ignored** — resume wins, enforced by dropping `state_save` at the control-pin latch. The operation is an ordinary cache-resume + finalize. With a block-aligned message the advanced slot already holds exactly what the save would have stored; note that the finalize length seed still assumes a single-block original prefix.

A prefix is therefore hashed once and reused across many message hashes at zero per-message state-transfer cost — the building block for fixed-prefix PQC hashing (e.g. SLH-DSA `PK.seed`, XMSS `SEED`). The cache holds one slot and reuses the existing state registers (no dedicated storage). It covers all SHA-2 modes, including the SHA-256/224 duet (both mirrored and independent per-lane messages). The slot survives interleaved SHA-3/SHAKE operations (they never touch the SHA-2 chaining registers) but is invalidated by any intervening SHA-2 hash and destroyed by `zeroize`. When `state_cache` is low, save/load use the streamed context-switching flow above (and that remains the only path for SHA-3/SHAKE).

## Core configuration options

SHARMONY's compile-time configuration lives in `essec_sharmony_pkg.sv` as `*_DEFAULT` localparams and is surfaced as module parameters that default to them: `REG_IO` (I/O-boundary registering, default `1'b1`), `ROM_USE_BRAM` (round-constants ROM implementation, default `1'b1`), and `ADDER_IMPL` (SHA-2 adder carry-chain implementation, default `ADDER_CARRY4`). `essec_sharmony_top` forwards them to its submodules, so an integrator can override them per instance without editing the package. All combinations are functionally identical — same digests, same ready/valid handshake protocol — and differ only in I/O latency, port timing, and resource cost.

**`REG_IO` — I/O boundary registering:**

- **`REG_IO = 1` (registered I/O, default).** All control/data inputs and the digest/XOF outputs are registered, giving a register-isolated I/O boundary. The full clock period is available to the internal datapath, and the integrating system sees only short clock-to-out and setup paths at the ports. Cost: one to two extra cycles of I/O latency and ~270 additional flip-flops.
- **`REG_IO = 0` (combinational I/O).** The I/O boundary is combinational (no boundary registers). This removes the I/O-buffer latency and saves the boundary flip-flops (plus a few LUTs), but exposes deep combinational paths at the ports (~5–6 ns) — and a direct input-to-output combinational path — that the surrounding system must absorb in its own timing budget.

**`ROM_USE_BRAM` — round-constants ROM implementation:**

- **`ROM_USE_BRAM = 1` (block RAM, default).** The 168×64-bit SHA-2/SHA-3 round-constants ROM (`essec_sharmony_rom`) uses one block RAM tile (`rom_style="block"`), and the registered read is absorbed by the block RAM's internal output register.
- **`ROM_USE_BRAM = 0` (distributed).** The ROM is realized in fabric LUTs (`rom_style="distributed"`). This frees the block RAM tile but costs **~+310 LUTs and +65 flip-flops** (the output register becomes explicit fabric FFs); timing is unchanged. Use it when block RAM is the constrained resource.

**`ADDER_IMPL` — SHA-2 adder carry-chain implementation:**

Selects the carry resource used by the dual-mode 64-bit / 2×32-bit round adders (`essec_sharmony_add32_32`). All three options produce identical results and cycle counts; they differ only in which device-family carry primitive the adders map to.

- **`ADDER_IMPL = ADDER_GENERIC` (portable).** A plain behavioral `+`, leaving the synthesis tool to infer whatever carry resource the target provides. Family-neutral — the right choice for non-Xilinx FPGAs and for ASIC mapping, and the configuration used for the *ASIC area* figures below.
- **`ADDER_IMPL = ADDER_CARRY4` (Xilinx 7-series, default).** Explicit `CARRY4` + `MUXCY` carry chain, matching the `xc7a200t` synthesis flow used for the figures above. Use on 7-series parts (Artix-7 / Kintex-7 / Virtex-7, Zynq-7000).
- **`ADDER_IMPL = ADDER_CARRY8` (UltraScale / UltraScale+).** Explicit `CARRY8` carry chain for UltraScale and UltraScale+. Not a 7-series primitive.

### Resource utilization

Figures below are for the **default configuration** (`ROM_USE_BRAM = 1`). Selecting `ROM_USE_BRAM = 0` removes the block RAM and adds ~310 LUTs / 65 FFs (see above).

| Resource | `REG_IO = 1` (registered, default) | `REG_IO = 0` (combinational) |
|---|---:|---:|
| Slice LUTs (total) | 5873 | 6044 |
| &nbsp;&nbsp;— LUT as logic | 5745 | 5916 |
| &nbsp;&nbsp;— LUT as memory (SRL16E) | 128 | 128 |
| Slice registers (FF, all FDRE) | 2310 | 2039 |
| CARRY4 | 254 | 254 |
| Block RAM (RAMB36E1) | 1 | 1 |
| DSP slices | 0 | 0 |

### Timing and I/O delay

| Characteristic | `REG_IO = 1` (registered) | `REG_IO = 0` (combinational) |
|---|---:|---:|
| Internal Fmax (register-to-register, SHA-2 round path) | 132 MHz | 132 MHz |
| Worst input port → first flip-flop | ~2.5 ns (2 levels, `resetn`) | ~5.8 ns (deep `byte_len` count path) |
| Worst last flip-flop → output port (clock-to-out) | ~1.0 ns (0 levels) | ~5.4 ns (`output_data`) |
| Combinational input → output path | none | present |
| I/O latency overhead (start → first output) | +3 cycles | none |

Figures are from Vivado out-of-context synthesis for `xc7a200tfbg484-3` (Artix-7, speed grade −3) with a 10 ns clock constraint and the default synthesis directive. The I/O ports carry no input/output-delay constraints, so the delays above are the measured worst-case combinational path delays at the boundary, and the internal Fmax reflects the register-to-register critical path (the SHA-2 round chain: the Σ1/Ch/adder path updating E), which is identical for both configurations. With `REG_IO = 1` every data port presents at logic depth 0 except `output_ready` (1 level), `zeroize` and `resetn` (2 levels), and `start` and `input_valid`/`input_final` (3 levels, the back-pressure decode); the control input `mode` is directly registered (depth 0) in **both** configurations; `state_load`, `state_save`, and `state_cache` see one LUT level (~0.8 ns) — the resume-wins guard `state_save && !(state_load && state_cache)` in front of the `state_save` latch. All flip-flops use synchronous reset and map to the FDRE primitive. `output_data` is driven to zero whenever `output_valid` is low. Neither configuration uses DSP slices.

### ASIC area (gate equivalents)

Technology-independent area, from an open-source ASIC mapping (`make synth-yosys`): yosys + the slang SystemVerilog frontend, mapped to the **Nangate 45 nm Open Cell Library** (`typical` corner) with module boundaries preserved. For a fabric-neutral result the design is synthesized in its generic configuration — `ADDER_IMPL = GENERIC` (no Xilinx `CARRY4`) and `ROM_USE_BRAM = 0` (round-constants ROM as standard-cell logic). One gate equivalent (GE) is the area of a 2-input NAND (`NAND2_X1`, 0.798 µm²). This is an unconstrained area metric (no clock/timing constraints), so absolute counts differ from the Artix-7 LUT/FF figures above.

| Component | `REG_IO = 1` (kGE) | `REG_IO = 0` (kGE) |
|---|---:|---:|
| Hash core — control + datapath (excl. SHA-2 adders) | 45.7 | 43.2 |
| SHA-2 round adders (13 dual-mode, 64-bit or 2×32-bit) | 6.3 | 6.3 |
| Padding front-end (`essec_sharmony_pad`) | 3.2 | 2.5 |
| Round-constants ROM (distributed) | 1.7 | 1.7 |
| Top-level I/O glue | 0.1 | 0.1 |
| **Total** | **57.0** | **53.8** |

### Latency

Cycle-accurate latency for a single-block hash, taken from simulation (SHA-224, one 512-bit block). Cycles are edge-counted, matching the `make run-performance` metrics:

| Latency | `REG_IO = 1` | `REG_IO = 0` |
|---|---:|---:|
| start → first `output_valid` | 68 cycles | 65 cycles |
| start → `busy` deasserted | 73 cycles | 72 cycles |

The **end-to-end latency** (start → `busy` deasserted, **73** for `REG_IO = 1`) matches the performance test's `end-to-end (start->done)` metric and the SHA-224 row of the per-mode table below. The registered I/O boundary (`REG_IO = 1`) adds **+3 cycles** to the host-visible start→first-output latency (≈1 input + 2 output register stages) versus the combinational `REG_IO = 0` boundary. Latency scales with message length by the per-block cost: an *N*-block message takes `Fixed + N × Per-block` cycles. Per-mode cycle counts and throughput are tabulated below.

Per-mode figures from `make run-performance` for the default `REG_IO = 1` configuration at `f_clk = 132 MHz` (the performance-test default, ≈ the internal Fmax from *Timing and I/O delay*). *1-block latency* is the edge-counted end-to-end time (external `start` asserted → `busy` deasserted) for a single-block message; *Per-block* is the steady-state cost of one additional compression/permutation block; *Throughput* is the long-message rate `8 × rate_bytes × f_clk / Per-block`:

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

**Duet** runs SHA-224/256 as two independent 32-bit lanes in lockstep: identical cycle count, double the throughput (128-byte block-pair vs 64-byte single lane). **SHAKE** rows are extendable-output (XOF); the throughput shown is the absorb/squeeze rate and scales with the requested output length. Throughput scales linearly with `f_clk`. Full per-mode cycle-phase breakdowns (`Fixed = Lead + Init + Tail − Gap`, `Per-block = Rounds + Absorb + Gap`) are printed by `make run-performance` (and `VERBOSE=1` for the FSM-state detail).

## Repository structure

```text
SHARMONY/
├── docs/
│   ├── figures/                   # block diagrams and figures
│   ├── waveforms/                 # rendered timing-diagram figures (PDF)
│   └── sharmony_hw_spec.pdf       # hardware specification document
├── hw/
│   └── sharmony/                  # SHARMONY RTL source files
│       ├── essec_sharmony_*.sv    # pkg, top, core, pad, rom, adders (add32_32 / add32_c4 / add32_c8 / add4_c4 / add8_c8)
│       └── CARRY4.v, CARRY8.v, MUXCY.v  # Xilinx carry-primitive sim models (Apache-2.0, see file headers)
├── synth/                         # out-of-context synthesis flows (Vivado / yosys)
│   ├── sharmony_top/              # SHARMONY core OOC synth (make synth-vivado)
│   ├── lib/                       # Nangate45 liberty goes here (not bundled, see Requirements)
│   ├── work/                      # generated reports / checkpoints — gitignored
│   ├── ge_table.awk               # builds the ASIC gate-equivalent (kGE) area table
│   └── vivado_tables.awk          # formats Vivado resource/timing/I-O tables
├── tb/
│   ├── src/                       # active Verilator/C++ simulation flow
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
├── Makefile                       # build, lint, test, waveform, and clean targets
└── README.md
```

## Requirements

Simulation and tests:

- Verilator 5.x — a recent release is recommended (verified with Verilator 5.048)
- GNU Make
- A C++ compiler (g++ or clang++; used by the Verilator build)

Waveform viewing (`make vcd-<TESTNAME>`, optional):

- Surfer waveform viewer (https://surfer-project.org)

ASIC synthesis (`make synth-yosys`, optional):

- yosys with the slang plugin (e.g. the OSS CAD Suite)
- The Nangate 45 nm Open Cell Library liberty file, which is **not bundled** (its
  license differs from this repository's Apache-2.0). Download
  `NangateOpenCellLibrary_typical.lib` — e.g. from the OpenROAD-flow-scripts
  repository under `flow/platforms/nangate45/lib/` — and place it at
  `synth/lib/NangateOpenCellLibrary_typical.lib`, or point the build at it with
  `make synth-yosys NANGATE_LIB=/path/to/NangateOpenCellLibrary_typical.lib`.

## Verification methodology

Verification is based on NIST test vectors:

- CAVP SHAVS vectors for SHA-2.
- CAVP SHA3VS vectors for SHA-3 and SHAKE.
- NIST SP 800-185 Appendix A sample vectors for cSHAKE128/cSHAKE256.

## Available tests

Tests are registered as C++ scenarios under `tb/src/tests/*_test.cpp`. The response vectors are stored under `tb/src/tests/data/*.rsp`. To list the available tests, run:

```bash
make list-tests
```

Example output:

```text
========================== Available tests =============================
 SHA-2                    SHA-3                    SHAKE
 -----                    -----                    -----
 sha224_shortmsg          sha3_224_shortmsg        shake128_shortmsg
 sha224_longmsg           sha3_224_longmsg         shake128_longmsg
 sha224_monte             sha3_224_monte           shake128_monte
 sha256_shortmsg          sha3_256_shortmsg        shake128_variableout
 sha256_longmsg           sha3_256_longmsg         shake256_shortmsg
 sha256_monte             sha3_256_monte           shake256_longmsg
 sha384_shortmsg          sha3_384_shortmsg        shake256_monte
 sha384_longmsg           sha3_384_longmsg         shake256_variableout
 sha384_monte             sha3_384_monte           cshake128
 sha512_shortmsg          sha3_512_shortmsg        cshake256
 sha512_longmsg           sha3_512_longmsg
 sha512_monte             sha3_512_monte
 sha512_224_shortmsg
 sha512_224_longmsg
 sha512_224_monte
 sha512_256_shortmsg
 sha512_256_longmsg
 sha512_256_monte

 Other tests:
 shortmsg    - Tests short message hashing and padding paths
 longmsg     - Tests long multi-block message processing
 interface   - Tests streaming and control interface operation
 error       - Verifies invalid input and error handling paths
 performance - Measures throughput, latency, and cycle counts
 nightly     - Runs the complete regression test suite
 midstate    - Tests midstate save/load and internal state caching
 zeroize     - Verifies zeroization behavior corner cases
----------------------------------------------------------------------
 Run with: make run-<TESTNAME>
======================================================================
```

The listed tests have passed or have been exercised at least once in the current verification setup.

## How to run

Run commands from the project root, i.e., the directory containing `Makefile`.

### Quick run

```bash
make run-sha256_shortmsg
```

### Run with VCD waveform generation

```bash
make run-sha512_shortmsg VCD=1
```

Generated artifacts:

- Log: `tb/work/logs/<TESTNAME>/log`
- Waveform: `tb/work/vcd/sha512_shortmsg.vcd`

## Acknowledgement

This work has received funding from the EU’s Horizon Europe research and innovation programme under grant agreement No. 101225722 (FORTRESS)

## License / copyright

Copyright © 2025-2026 Universität der Bundeswehr München / Research Institute CODE - ESSEC Lab.

Lab-authored code is licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE) and the SPDX headers in each file. The Xilinx carry-primitive simulation models (`hw/sharmony/CARRY4.v`, `CARRY8.v`, `MUXCY.v`) are Xilinx-copyrighted and Apache-2.0-licensed (see their file headers). The Nangate 45 nm Open Cell Library used by the optional ASIC synthesis flow is not bundled; it is downloaded separately under its own license (see Requirements).
