# SHARMONY tests

The testbench is a Verilator/C++ flow: `make build` compiles the RTL and every test into one binary, `tb/work/obj_dir/Vsharmony_verilator_wrapper`; `make run-<TESTNAME>` runs one test and writes its output to `tb/work/logs/<TESTNAME>/log`. Run every `make` from the repository root. The requirements are in the root [README](../README.md).

## What is tested, against what

`make list-tests` prints the registered names, the KATs in three columns (SHA-2, SHA-3, SHAKE) and the scenario tests with a one-line description each:

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

| Tests | Vectors | What they check |
|---|---|---|
| `sha224_shortmsg` … `sha512_256_longmsg` (SHA-2), `sha3_224_shortmsg` … `sha3_512_longmsg` (SHA-3) | NIST CAVP SHAVS / SHA3VS `ShortMsg` and `LongMsg` response files | Every vector's digest, in two phases: reset before every vector, then one reset and all vectors chained. SHA-224/256 run in the duet: the same message in both 32-bit lanes, each lane's digest checked. |
| `*_monte` | CAVP Monte Carlo files | The 100 checkpoints of the 1000-iteration sequences: SHA-2 the three-message sliding window, SHA-3 the simple chain, SHAKE the SHAKE Monte Carlo with its varying output length. |
| `shake128_*`, `shake256_*` | CAVP SHAKE `ShortMsg`, `LongMsg`, `Monte`, `VariableOut` | The XOF output: `shortmsg` / `longmsg` check the first 16 bytes, `variableout` the full requested output length per vector (the consumer collects ⌈Outputlen/64⌉ beats and stops the squeeze). |
| `cshake128`, `cshake256` | NIST SP 800-185 Appendix A samples | The customization: the `bytepad(encode_string(N) ‖ encode_string(S), rate)` preamble is built in software and streamed ahead of the message. |
| `shortmsg`, `longmsg`, `nightly` | the files above | Aggregates: every `ShortMsg` / `LongMsg` KAT across all modes (`shortmsg` includes the duet cross-lane pairing, two different vectors in the two lanes), and the whole suite. |
| `interface` | one KAT per mode, and `RefHash` | The ready/valid and control protocol in all 12 hash/XOF modes: resets at every point of a transaction (idle, after `start`, mid-stream, during the output, under back-pressure), input gaps, output back-pressure in several patterns, back-to-back transactions, `start`, `zeroize` and `mode` changes while busy, the XOF squeeze-stop, staggered duet lanes; each scenario's digest checked. |
| `error` | none | Illegal and suspicious sequences at the top level: no false digest, no hang, clean recovery after reset. |
| `zeroize` | none | The `zeroize` line: every sensitive register clears within the window, recovery without reset, chained scenarios. |
| `midstate` | none | `state_save` / `state_load` / `state_cache`: save/load round trips in every mode, resume-and-finalize digests, the cache slot and its corner cases. |
| `performance` | none | Cycle counts per mode: latency, per-block cost, throughput at `FREQ_MHZ` (default 132). |

`tests/common/RefHash` is a software golden model of every mode but cSHAKE: the interface test uses it to check digests of arbitrary messages, and a new scenario test can do the same. `error`, `zeroize` and `midstate` check behaviour (no false digest, cleared registers, round trips), not digests.

## Running

```bash
make list-tests                              # the registered tests
make build                                   # once, and after every RTL or test change
make run-sha256_shortmsg                     # one test
make run-sha3_512_longmsg MAX_VECTORS=10     # the first 10 vectors only
make run-sha512_shortmsg VCD=1               # with a waveform in tb/work/vcd/sha512_shortmsg.vcd
make vcd-sha256_shortmsg                     # open the waveform in Surfer (runs the test first if there is none)
make run-sha256_shortmsg VERBOSE=2           # one line per vector, the messages, digests and beats
make run-nightly                             # the whole suite
```

| Option | Meaning |
|---|---|
| `VERBOSE=<0,1,2>` | Output detail, below. |
| `MAX_VECTORS=<n>` | Run only the first n vectors of a KAT test (0 = all, the default). |
| `VCD=1` | Write `tb/work/vcd/<TESTNAME>.vcd`. |
| `RSP=<path>` | Use another NIST response file for a KAT test. |
| `FREQ_MHZ=<MHz>` | The clock the performance test converts cycles to throughput with. |

The binary takes the same as command-line options (`--test`, `--verbose`, `--max-vectors`, `--vcd`, `--rsp`, `--freq-mhz`), plus `--mode <NAME>` to run a scenario test in one mode only (e.g. `--mode HASH_SHA2_256`, `--mode XOF_SHAKE128`) and `--list-tests`; `tb/work/obj_dir/Vsharmony_verilator_wrapper --help` prints them. Exit code 0 on pass, 1 on fail, 2 on a usage error.

## Output and verbosity

A KAT test runs its vectors twice: phase 1 resets the core before every vector, phase 2 resets once and chains the vectors back to back.

- **`VERBOSE=0` (default):** the number of vectors loaded, the two phase headers, the pass / fail count of each phase, the test's verdict and the summary. A failing vector is always reported with its length, a preview of the message, and the expected and the computed digest (`exp =` / `got =`); a phase stops after five failures (a Monte Carlo test after three).
- **`VERBOSE=1`:** one `[PASS]` line per vector and phase with its length in bits (SHAKE variable-output tests: the output length; Monte Carlo tests: the checkpoint). The performance test adds the per-mode FSM-state breakdown and the busy-cycle totals.
- **`VERBOSE=2`:** additionally the message preview, the digest and every output beat of the vector as hex (the SHA-224/256 duet tests show both lanes of each beat), the cSHAKE outputs, and a progress line every 100 inner iterations of a Monte Carlo checkpoint.

`make run-sha512_shortmsg MAX_VECTORS=2 VERBOSE=2`:

```text
>>> Running sha512_shortmsg
[sha512_shortmsg] 129 vectors loaded from tb/src/tests/data/SHA512ShortMsg.rsp
[sha512_shortmsg] phase 1: reset-per-vector
[PASS] sha512_shortmsg P1 vector 0 Len=0
       Msg = (empty)
       MD  = cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
       beat[0] = cf83e1357eefb8bd
       beat[1] = f1542850d66d8007
       ...
       beat[7] = a538327af927da3e
[PASS] sha512_shortmsg P1 vector 1 Len=8
       Msg = 21
       MD  = 3831a6a6155e509dee59a7f451eb35324d8f8f2df6e3708894740f98fdee23889f4de5adb0c5010dfb555cda77c8ab5dc902094c52de3278f35a75ebc25f093a
       ...
[sha512_shortmsg] phase 2: single-reset + chain (no per-vector reset)
       ...
[sha512_shortmsg] phase 1 (reset/vector): 2 pass / 0 fail
[sha512_shortmsg] phase 2 (1 reset+chain): 2 pass / 0 fail
[sha512_shortmsg] (cap=2 run, 129 loaded)
[PASS] sha512_shortmsg
Summary: 1 passed, 0 failed
```

The beats are printed in digest order, `beat[0]` being the first 8 bytes of `MD`: for SHA-2 the runner has already undone the core's reverse word order (`std::reverse` in `HashKatTest.cpp`; the core emits the highest word first, see the output word order in [hw/sharmony/README.md](../hw/sharmony/README.md)); SHA-3 and SHAKE beats come out of the core in this order. The SHA-224/256 tests run the message mirrored in both duet lanes and print both lanes of each beat.

## Layout

```text
tb/
├── src/
│   ├── sharmony_verilator_wrapper.sv   # the simulation top: essec_sharmony_top with flat ports
│   ├── main.cpp                        # option parsing, test dispatch, exit code
│   ├── SharmonyDriver.{cpp,hpp}        # drives the streaming interface cycle by cycle
│   ├── TestRegistry.{cpp,hpp}          # the test registry and REGISTER_TEST
│   ├── RspParser.{cpp,hpp}             # reads NIST .rsp response files
│   └── tests/
│       ├── data/*.rsp                  # the NIST vectors
│       ├── common/                     # the runners the tests are built from (below)
│       └── *_test.cpp                  # one registered test per file
└── work/                               # build, logs, VCDs (generated)
```

The runners in `tests/common/`:

| Runner | Used by |
|---|---|
| `HashKatTest` | SHA-2 (384 and up) and SHA-3 `shortmsg` / `longmsg`: a `Len` / `Msg` / `MD` file against one mode |
| `HashKatDuetTest`, `HashKatPairDuetTest` | SHA-224/256 `shortmsg` / `longmsg`: the same vector mirrored in both lanes; the cross-lane pairing of two vectors in the `shortmsg` aggregate |
| `MonteTest` | the SHA-2 and SHA-3 `*_monte` |
| `ShakeKatTest`, `ShakeXofTest` | the SHAKE `shortmsg` / `longmsg` (`ShakeKatTest`), `variableout` and `monte` (`ShakeXofTest`) |
| `CShakeKatTest` | `cshake128`, `cshake256` |
| `ScenarioCommon`, `RefHash` | the mode sweep and the `--mode` filter of the scenario tests; the software reference (the interface test) |
| `AggregateRunner` | `shortmsg`, `longmsg`, `nightly` |

`SharmonyDriver` is the model of the host: `reset()`, `setMode()`, the state pins (`setStateLoad` / `setStateSave` / `setStateCache`), `pulseStart()`, `sendBeat()` and `sendMessageNative()` for the 64-bit stream, `sendBeatDuet()` / `sendMessageDuetMirror()` / `sendMessagesDuet()` for the two SHA-224/256 lanes, `endMsg()`, `collectBeats(n)` for the output, `setOutReady()` and `setZeroize()` for the control lines, the `try*` variants that return instead of throwing on a timeout (the error test), `beatsToBytes()` to turn beats into a digest, and `sensitiveRegsZero()` for the zeroize test.

## Adding a test

A test is one function registered under a name; the Makefile finds every `tests/<name>_test.cpp` and `make list-tests` shows it, nothing else to edit.

1. A KAT against a NIST response file: create `tests/<name>_test.cpp` from an existing one and change the mode, the file and the name:

   ```cpp
   #include "common/HashKatTest.hpp"
   namespace sharmony {
   static int run_sha384_shortmsg(SharmonyDriver& drv, const TestOptions& opts) {
       return runHashKat(drv, opts, Mode::SHA2_384,
                         "tb/src/tests/data/SHA384ShortMsg.rsp", "sha384_shortmsg");
   }
   REGISTER_TEST("sha384_shortmsg", run_sha384_shortmsg);
   }
   ```

   `runHashKatDuet` (SHA-224/256), `runShakeKat`, `runShakeVariableOut`, `runShakeMonte` and `runCShakeKat` take the same arguments; `runMonte` takes the Monte family (`MonteFamily::Sha2` or `Sha3`) after the mode. A file put under `tests/data/` is picked up by its path; `RSP=<path>` overrides it at run time.

2. A scenario of your own: drive the core with `SharmonyDriver` and compare against `refHash(mode, message, xof_len)` (the output length for SHAKE, ignored otherwise); the function returns 0 on pass and prints its own `[PASS]` / `[FAIL]` lines, `opts.verbosity` says how much (0, 1, 2 as above), `opts.max_vectors` caps loops, `opts.mode_filter` is the `--mode` name when given. `interface_test.cpp` and `zeroize_test.cpp` are the patterns.

3. `make build && make run-<name>`. A name of the form `<stem>_<kind>` with a known stem (`sha224` … `sha512_256`, `sha3_224` … `sha3_512`, `shake128`, `shake256`) and kind (`shortmsg`, `longmsg`, `monte`), or `cshake128` / `cshake256`, lands in its column of `make list-tests`; any other name goes under *Other tests*, with a description if one is added to the `case` list of the `list-tests` target in the Makefile.
