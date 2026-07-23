///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// C++ driver wrapping the Verilator model. Provides BFM-style tasks (reset,
// start pulse, message-beat streaming, digest collection, etc.) with timeout
// protection on every handshake. input_valid stays asserted between beats;
// the next beat overwrites the data fields and endMsg() ends the stream.
//
// Mode encoding follows sharmony_pkg::mode_e (4-bit, see wrapper for values).
//
///////////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <cstdint>
#include <memory>
#include <functional>
#include <string>
#include <vector>
#include <utility>

class Vsharmony_verilator_wrapper;   // forward decl - Verilator-generated
class VerilatedContext;
class VerilatedVcdC;

namespace sharmony {

enum class Mode : uint8_t {
    SHA2_224       = 0x0,
    SHA2_256       = 0x1,
    SHA2_384       = 0x2,
    SHA2_512       = 0x3,
    SHA2_512_224   = 0x4,
    SHA2_512_256   = 0x5,
    SHA3_224       = 0x6,
    SHA3_256       = 0x7,
    SHA3_384       = 0x8,
    SHA3_512       = 0x9,
    SHAKE128       = 0xA,
    SHAKE256       = 0xB,
    CSHAKE128      = 0xC,
    CSHAKE256      = 0xD
};

// Bytes per native 64-bit beat = 8. Returns digest size in beats for a mode.
int digestBeatsFor(Mode m);
// Returns digest size in bytes for a mode (XOF defaults to 16 = 2 beats).
int digestBytesFor(Mode m);
const char* modeName(Mode m);

struct TimeoutError : public std::exception {
    std::string msg;
    explicit TimeoutError(std::string m) : msg(std::move(m)) {}
    const char* what() const noexcept override { return msg.c_str(); }
};

class SharmonyDriver {
public:
    using TickHook = std::function<void(const Vsharmony_verilator_wrapper&, uint64_t)>;

    // Constructs the Verilator model. If vcd_path is non-empty, opens a VCD
    // trace for the lifetime of the driver.
    SharmonyDriver(int argc, char** argv, const std::string& vcd_path);
    ~SharmonyDriver();

    SharmonyDriver(const SharmonyDriver&) = delete;
    SharmonyDriver& operator=(const SharmonyDriver&) = delete;

    //---------------------------------------------------------------------------------
    //  Clock / reset
    //---------------------------------------------------------------------------------
    // Advance one full clock cycle, ending on the closing rising edge (see
    // the tick() comment in the .cpp). Returns true if a beat transfer
    // occurred at this posedge (input_valid && input_ready sampled BEFORE
    // the posedge).
    bool tick();
    void tick(unsigned n);

    // Hold resetn low for `cycles` ticks, then release and wait 2 settling
    // cycles.
    void reset(int cycles = 20);

    //---------------------------------------------------------------------------------
    //  Control
    //---------------------------------------------------------------------------------
    // Set the mode register. Safe only when DUT is idle.
    void setMode(Mode m);
    // Midstate caching qualifiers (sampled with start). Drive before pulseStart.
    void setStateLoad(bool assert_high);
    void setStateSave(bool assert_high);
    void setStateCache(bool assert_high);

    // Wait until not busy, then pulse start for one cycle. Throws on
    // timeout.
    void pulseStart(unsigned timeoutCycles = 500);

    //---------------------------------------------------------------------------------
    //  Input streaming
    //---------------------------------------------------------------------------------
    // Drive one beat and wait until it is accepted (input_valid &&
    // input_ready). Leaves input_valid and the data/bytes/final lines
    // driven: the next beat overwrites them, endMsg() deasserts.
    // Throws TimeoutError on timeout.
    void sendBeat(uint64_t data, uint8_t bytes, uint8_t final_bits,
                  unsigned timeoutCycles = 1000);

    // Send a full message as a sequence of native 64-bit beats, MSB-first
    // byte packing within each beat. The last beat carries input_final=2'b11
    // and a possibly-partial byte count. An empty message produces one beat
    // with bytes=0 and input_final=2'b11.
    void sendMessageNative(const std::vector<uint8_t>& msg,
                           unsigned timeoutCycles = 1000);

    //---------------------------------------------------------------------------------
    //  Duet streaming (SHA-224/256 duet build)
    //---------------------------------------------------------------------------------
    // Drive one duet beat. Packs hi/lo into the 64-bit bus:
    //   input_data[63:32]  = hi_data,  [31:0]  = lo_data
    //   input_bytes[5:3]   = hi_bytes, [2:0]   = lo_bytes
    //   input_final[1]     = hi_final, [0]     = lo_final
    void sendBeatDuet(uint32_t hi_data, uint8_t hi_bytes, uint8_t hi_final,
                      uint32_t lo_data, uint8_t lo_bytes, uint8_t lo_final,
                      unsigned timeoutCycles = 1000);

    // Send the same message on BOTH lanes (mirror mode). 4 bytes per lane per
    // beat, MSB-first within each lane. Used by any duet-build test streaming
    // one logical message (KAT, Monte, zeroize, midstate flows) - both lanes
    // compute the hash independently, so output beats should have hi == lo.
    void sendMessageDuetMirror(const std::vector<uint8_t>& msg,
                               unsigned timeoutCycles = 1000);

    // Asymmetric duet: drive TWO independent messages, one on each lane,
    // for potentially different lengths. Per the DUT contract:
    //   - Each beat carries up to 4 bytes per lane (MSB-first within lane).
    //   - When a lane reaches its last byte, that beat asserts <lane>_final=1.
    //   - Once a lane has finalized, all subsequent beats drive that lane
    //     IDLE: data=0, bytes=0, final=0. The other lane keeps streaming.
    //   - Loop ends when BOTH lanes have finalized.
    //   - Both messages empty -> single terminal beat with both finals=1.
    // Used by the duet KAT pairs and the duet flows in the midstate,
    // interface, and performance tests.
    void sendMessagesDuet(const std::vector<uint8_t>& msg_hi,
                          const std::vector<uint8_t>& msg_lo,
                          unsigned timeoutCycles = 1000);

    // Drop input_valid and clear the data lines.
    void endMsg();

    //---------------------------------------------------------------------------------
    //  Output collection
    //---------------------------------------------------------------------------------
    // Collect N consecutive digest beats. Resets the per-beat timeout each
    // time a beat is received.
    std::vector<uint64_t> collectBeats(size_t n, unsigned timeoutPerBeat = 10000);

    //---------------------------------------------------------------------------------
    //  Non-throwing variants used by error/reset scenario tests
    //---------------------------------------------------------------------------------
    // These never throw on timeout - they return false instead. They are
    // intended for negative/protocol tests where blocking forever would be
    // bad and a clean "the DUT didn't accept" answer is what we want.
    bool tryPulseStart(unsigned timeoutCycles);

    // Drive one beat, return true if accepted within timeout. Inputs are
    // LEFT in the state they were driven in.
    // Caller should call forceIdleInputs() / endMsg() / reset() afterward.
    bool trySendBeat(uint64_t data, uint8_t bytes, uint8_t final_bits,
                     unsigned timeoutCycles);
    bool trySendBeatDuet(uint32_t hi_data, uint8_t hi_bytes, uint8_t hi_final,
                         uint32_t lo_data, uint8_t lo_bytes, uint8_t lo_final,
                         unsigned timeoutCycles);

    // Wait for output_valid=1 within the timeout. Returns true if seen.
    bool waitOutputValid(unsigned timeoutCycles);

    // Try-collect: returns (true, beats) on success, (false, partial) on
    // timeout. Per-beat timeout, like collectBeats().
    std::pair<bool, std::vector<uint64_t>>
        tryCollectBeats(size_t n, unsigned timeoutPerBeat);

    //---------------------------------------------------------------------------------
    //  Misc control utilities
    //---------------------------------------------------------------------------------
    // Drive every TB-driven stim signal to its idle value and run one tick
    // so the new state is sampled. Use this before reset() in error tests
    // (where a try_* may have left signals in a half-driven state) and as a
    // belt-and-braces clear at scenario boundaries.
    void forceIdleInputs();

    // Drive the zeroize line. The DUT acts on it combinationally / on the
    // next posedge.
    void setZeroize(bool assert_high);

    // Drive the output_ready line (default state is 1, backpressure = 0).
    void setOutReady(bool assert_high);

    //---------------------------------------------------------------------------------
    //  Probes
    //---------------------------------------------------------------------------------
    bool outputValid() const;
    bool inputReady() const;
    bool busy() const;
    // Convenience alias: the engine is ready to accept a new start when not busy.
    bool acceptStart() const;
    uint64_t outputData() const;

    // Security: read all sensitive registers (key/message-derived state) via
    // Verilator public_flat_rd probes and report whether they are ALL zero.
    // On a non-zero hit, *firstNonzero (if given) names the offending register.
    // Covers core R_q[0:24], H_q[0:7], u_data, output_data_b, skid_data and
    // pad in_data_q, in_bytes_q. Used by the zeroize-scrub test.
    bool sensitiveRegsZero(std::string* firstNonzero = nullptr) const;

    // Convert a vector of 64-bit beats (big-endian within beat) to a byte
    // vector of the requested length. Used to compare against .rsp MD fields.
    static std::vector<uint8_t> beatsToBytes(const std::vector<uint64_t>& beats,
                                             size_t n_bytes);

    // Extract the lo-lane (32-bit, [31:0]) bytes from duet beats, MSB-first
    // within each lane. SHA-224 (duet) -> 7 beats x 4 bytes = 28 bytes.
    // SHA-256 (duet) -> 8 beats x 4 bytes = 32 bytes.
    static std::vector<uint8_t> beatsToLoLaneBytes(const std::vector<uint64_t>& beats,
                                                   size_t n_bytes);

    // Extract the hi-lane (32-bit, [63:32]) bytes from duet beats. Used by
    // duet tests to cross-check that hi == lo when running mirror stimulus.
    static std::vector<uint8_t> beatsToHiLaneBytes(const std::vector<uint64_t>& beats,
                                                   size_t n_bytes);

    static std::string bytesToHex(const std::vector<uint8_t>& bytes);

    //---------------------------------------------------------------------------------
    //  Counters
    //---------------------------------------------------------------------------------
    uint64_t cycle() const { return cycle_count_; }

    Vsharmony_verilator_wrapper* model() { return top_.get(); }
    const Vsharmony_verilator_wrapper* model() const { return top_.get(); }

    void setTickHook(TickHook hook) { tick_hook_ = std::move(hook); }
    void clearTickHook() { tick_hook_ = nullptr; }

private:
    std::unique_ptr<VerilatedContext> ctx_;
    std::unique_ptr<Vsharmony_verilator_wrapper> top_;
    std::unique_ptr<VerilatedVcdC> tfp_;
    uint64_t cycle_count_ = 0;
    uint64_t sim_time_ns_ = 0;   // monotonically increasing; 5ns per half-cycle
    TickHook tick_hook_;

    void evalAndDump();
};

}  // namespace sharmony
