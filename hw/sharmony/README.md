# SHARMONY RTL

The SystemVerilog sources of the core. The root [README](../../README.md) has the requirements, the tests and the results; the [hardware specification](../../docs/sharmony_hw_spec.pdf) has the microarchitecture. This file describes what an integrator needs: the files, the modes, the top-level interface and the configuration parameters.

## Files

| File | Module | Role |
|---|---|---|
| `essec_sharmony_pkg.sv` | `essec_sharmony_pkg` | The `mode_e` encoding, the per-mode constants, the configuration defaults (`REG_IO_DEFAULT`, `ROM_USE_BRAM_DEFAULT`, `ADDER_IMPL_DEFAULT`). |
| `essec_sharmony_top.sv` | `essec_sharmony_top` | The integration wrapper: instantiates the padding front-end, the hash core and the round-constants ROM, and exposes the streaming interface below. |
| `essec_sharmony_pad.sv` | `essec_sharmony_pad` | The padding front-end: takes the message stream, assembles the blocks, applies the SHA-2 / SHA-3 / SHAKE / cSHAKE padding, feeds the core. |
| `essec_sharmony_core.sv` | `essec_sharmony_core` | The shared datapath and control: the 25×64-bit state register, the SHA-2 round logic (64-bit, or two 32-bit lanes in the SHA-224/256 duet), the Keccak-f[1600] round, the state save / load / cache paths, the digest and XOF output. |
| `essec_sharmony_rom.sv` | `essec_sharmony_rom` | The registered-read ROM of the SHA-2 K and SHA-3 iota round constants, 168 × 64 bit; block RAM or fabric logic by `ROM_USE_BRAM`. |
| `essec_sharmony_add32_32.sv` | `essec_sharmony_add32_32` | The dual-mode adder of the SHA-2 rounds: one 64-bit add or two independent 32-bit adds; its carry chain by `ADDER_IMPL`. |
| `essec_sharmony_add32_c4.sv`, `essec_sharmony_add4_c4.sv` | | The `CARRY4` chain of a 32-bit half (Xilinx 7-series) and its 4-bit slice. |
| `essec_sharmony_add32_c8.sv`, `essec_sharmony_add8_c8.sv` | | The `CARRY8` chain of a 32-bit half (UltraScale, UltraScale+) and its 8-bit slice. |
| `CARRY4.v`, `CARRY8.v`, `MUXCY.v` | | Xilinx carry-primitive simulation models for the two chains above (Xilinx-copyrighted, Apache-2.0, see the file headers); instantiated only when `ADDER_IMPL` selects the matching chain. |

Hierarchy: `essec_sharmony_top` → `pad_inst` (`essec_sharmony_pad`), `core_inst` (`essec_sharmony_core`), `constants_rom` (`essec_sharmony_rom`); the core holds the 13 `essec_sharmony_add32_32` adders, each of which holds two carry chains (`u_lo`, `u_hi`) of the selected kind, or a plain `+` when `ADDER_IMPL = ADDER_GENERIC`.

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

## Configuration

SHARMONY's compile-time configuration lives in `essec_sharmony_pkg.sv` as `*_DEFAULT` localparams and is surfaced as module parameters that default to them: `REG_IO` (I/O-boundary registering, default `1'b1`), `ROM_USE_BRAM` (round-constants ROM implementation, default `1'b1`), and `ADDER_IMPL` (SHA-2 adder carry-chain implementation, default `ADDER_CARRY4`). `essec_sharmony_top` forwards them to its submodules, so an integrator can override them per instance without editing the package. All combinations are functionally identical — same digests, same ready/valid handshake protocol — and differ only in I/O latency, port timing, and resource cost.

| Parameter | Values | Default | What it selects |
|---|---|---|---|
| `REG_IO` | `0`, `1` | `1` | Registered I/O boundary (`1`) or combinational ports (`0`) |
| `ROM_USE_BRAM` | `0`, `1` | `1` | The round-constants ROM in one block RAM (`1`) or in fabric logic (`0`) |
| `ADDER_IMPL` | `ADDER_GENERIC`, `ADDER_CARRY4`, `ADDER_CARRY8` | `ADDER_CARRY4` | The carry resource of the 13 dual-mode SHA-2 round adders |

**`REG_IO` — I/O boundary registering:**

- **`REG_IO = 1` (registered I/O, default).** All control/data inputs and the digest/XOF outputs are registered, giving a register-isolated I/O boundary. The full clock period is available to the internal datapath, and the integrating system sees only short clock-to-out and setup paths at the ports. Cost: one to two extra cycles of I/O latency and ~270 additional flip-flops.
- **`REG_IO = 0` (combinational I/O).** The I/O boundary is combinational (no boundary registers). This removes the I/O-buffer latency and saves the boundary flip-flops (plus a few LUTs), but exposes deep combinational paths at the ports (~5–6 ns) — and a direct input-to-output combinational path — that the surrounding system must absorb in its own timing budget.

**`ROM_USE_BRAM` — round-constants ROM implementation:**

- **`ROM_USE_BRAM = 1` (block RAM, default).** The 168×64-bit SHA-2/SHA-3 round-constants ROM (`essec_sharmony_rom`) uses one block RAM tile (`rom_style="block"`), and the registered read is absorbed by the block RAM's internal output register.
- **`ROM_USE_BRAM = 0` (distributed).** The ROM is realized in fabric LUTs (`rom_style="distributed"`). This frees the block RAM tile but costs **~+310 LUTs and +65 flip-flops** (the output register becomes explicit fabric FFs); timing is unchanged. Use it when block RAM is the constrained resource.

**`ADDER_IMPL` — SHA-2 adder carry-chain implementation:**

Selects the carry resource used by the dual-mode 64-bit / 2×32-bit round adders (`essec_sharmony_add32_32`). All three options produce identical results and cycle counts; they differ only in which device-family carry primitive the adders map to.

- **`ADDER_IMPL = ADDER_GENERIC` (portable).** A plain behavioral `+`, leaving the synthesis tool to infer whatever carry resource the target provides. Family-neutral — the right choice for non-Xilinx FPGAs and for ASIC mapping, and the configuration used for the ASIC area figures in the root README.
- **`ADDER_IMPL = ADDER_CARRY4` (Xilinx 7-series, default).** Explicit `CARRY4` + `MUXCY` carry chain, matching the `xc7a200t` synthesis flow used for the FPGA figures in the root README. Use on 7-series parts (Artix-7 / Kintex-7 / Virtex-7, Zynq-7000).
- **`ADDER_IMPL = ADDER_CARRY8` (UltraScale / UltraScale+).** Explicit `CARRY8` carry chain for UltraScale and UltraScale+. Not a 7-series primitive.

The cost of each choice in LUTs, flip-flops and block RAM is measured in the root README under *Results*.
