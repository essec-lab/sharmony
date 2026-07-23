///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "SharmonyDriver.hpp"

#include "Vsharmony_verilator_wrapper.h"
#include "Vsharmony_verilator_wrapper___024root.h"  // public_flat_rd internal probes
#include <verilated.h>
#include <verilated_vcd_c.h>
#if VM_COVERAGE
# include <verilated_cov.h>
# include <cstdlib>
#endif

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

namespace sharmony {

//-------------------------------------------------------------------------------------
//  Mode info
//-------------------------------------------------------------------------------------
int digestBeatsFor(Mode m) {
    // 64-bit output beats per digest. In the duet modes (SHA-224/256) each
    // beat carries one 32-bit digest word mirrored in both lanes.
    switch (m) {
        case Mode::SHA2_224:     return 7;
        case Mode::SHA2_256:     return 8;
        case Mode::SHA2_384:     return 6;
        case Mode::SHA2_512:     return 8;
        case Mode::SHA2_512_224: return 4;
        case Mode::SHA2_512_256: return 4;
        case Mode::SHA3_224:     return 4;
        case Mode::SHA3_256:     return 4;
        case Mode::SHA3_384:     return 6;
        case Mode::SHA3_512:     return 8;
        case Mode::SHAKE128:     return 2;
        case Mode::SHAKE256:     return 2;
        case Mode::CSHAKE128:    return 2;
        case Mode::CSHAKE256:    return 2;
    }
    return 4;
}

int digestBytesFor(Mode m) {
    switch (m) {
        case Mode::SHA2_224:     return 28;
        case Mode::SHA2_256:     return 32;
        case Mode::SHA2_384:     return 48;
        case Mode::SHA2_512:     return 64;
        case Mode::SHA2_512_224: return 28;
        case Mode::SHA2_512_256: return 32;
        case Mode::SHA3_224:     return 28;
        case Mode::SHA3_256:     return 32;
        case Mode::SHA3_384:     return 48;
        case Mode::SHA3_512:     return 64;
        case Mode::SHAKE128:     return 16;  // 2 beats x 8 bytes
        case Mode::SHAKE256:     return 16;
        case Mode::CSHAKE128:    return 16;
        case Mode::CSHAKE256:    return 16;
    }
    return 32;
}

const char* modeName(Mode m) {
    switch (m) {
        case Mode::SHA2_224:     return "HASH_SHA2_224";
        case Mode::SHA2_256:     return "HASH_SHA2_256";
        case Mode::SHA2_384:     return "HASH_SHA2_384";
        case Mode::SHA2_512:     return "HASH_SHA2_512";
        case Mode::SHA2_512_224: return "HASH_SHA2_512_224";
        case Mode::SHA2_512_256: return "HASH_SHA2_512_256";
        case Mode::SHA3_224:     return "HASH_SHA3_224";
        case Mode::SHA3_256:     return "HASH_SHA3_256";
        case Mode::SHA3_384:     return "HASH_SHA3_384";
        case Mode::SHA3_512:     return "HASH_SHA3_512";
        case Mode::SHAKE128:     return "XOF_SHAKE128";
        case Mode::SHAKE256:     return "XOF_SHAKE256";
        case Mode::CSHAKE128:    return "XOF_CSHAKE128";
        case Mode::CSHAKE256:    return "XOF_CSHAKE256";
    }
    return "<unknown>";
}

//-------------------------------------------------------------------------------------
//  Lifecycle
//-------------------------------------------------------------------------------------
SharmonyDriver::SharmonyDriver(int argc, char** argv,
                                const std::string& vcd_path)
    : ctx_(std::make_unique<VerilatedContext>()),
      top_(),
      tfp_()
{
    ctx_->commandArgs(argc, argv);
    top_ = std::make_unique<Vsharmony_verilator_wrapper>(ctx_.get());

    if (!vcd_path.empty()) {
        Verilated::traceEverOn(true);
        tfp_ = std::make_unique<VerilatedVcdC>();
        top_->trace(tfp_.get(), 99);
        tfp_->open(vcd_path.c_str());
    }

    // Initial pin state.
    top_->f_clk       = 0;
    top_->resetn     = 0;
    top_->start       = 0;
    top_->zeroize     = 0;
    top_->mode        = static_cast<uint8_t>(Mode::SHA2_512);
    top_->state_load  = 0;
    top_->state_save  = 0;
    top_->state_cache = 0;
    top_->input_data  = 0;
    top_->input_valid = 0;
    top_->input_bytes = 0;
    top_->input_final = 0;
    top_->output_ready   = 1;
    top_->eval();
}

SharmonyDriver::~SharmonyDriver() {
    if (tfp_) tfp_->close();
#if VM_COVERAGE
    // Coverage builds (--coverage-line/--coverage-toggle) dump per-run data on
    // teardown; VERILATOR_COV_FILE lets `make coverage` give each test its own
    // file for later merging. No-op in normal (non-coverage) builds.
    if (ctx_) {
        const char* cf = std::getenv("VERILATOR_COV_FILE");
        ctx_->coveragep()->write(cf ? cf : "coverage.dat");
    }
#endif
}

void SharmonyDriver::evalAndDump() {
    top_->eval();
    if (tfp_) tfp_->dump(sim_time_ns_);
}

//-------------------------------------------------------------------------------------
// Clock
//
// Vivado-style stimulus placement. Each tick is one clock period that ENDS on
// a held-high rising edge. Between ticks the clock stays HIGH, so any input a
// caller drives after tick() returns is a post-edge stimulus: it is dumped at
// a clk-high timestamp just after the previous rising edge, then sampled by
// THIS tick's closing rising edge. The stimulus transition therefore sits one
// edge BEFORE the edge that captures it (clk high), instead of collapsing both
// onto the same timestamp the way a rising-then-falling tick did.
//
// Per tick there are 3 dumps (10 ns period, 5 ns high / 5 ns low):
//   (1) post-edge stimulus  clk high, +1 ns   <- caller's just-driven inputs
//   (2) falling edge        clk low,  +5 ns
//   (3) rising edge         clk high, +10 ns  <- registers capture (1)'s inputs
//
// Functionally inert vs. the old tick: identical sampling edges, cycle counts,
// and handshake behaviour -- only VCD timestamps / visual placement change.
// (First tick after construction starts from clk=0 in the reset region, which
// is harmless; the clk-high-between-ticks invariant holds from then on.)
//-------------------------------------------------------------------------------------
bool SharmonyDriver::tick() {
    // (1) Post-edge stimulus dump. The clock is high (held from the previous
    //     tick's closing rising edge) and the caller's just-driven inputs are
    //     live, so the stimulus transition is recorded here, just after the
    //     edge -- not on top of the edge that samples it.
    sim_time_ns_ += 1;
    evalAndDump();

    // Handshake intent for this cycle: the inputs just driven are exactly what
    // the closing rising edge (3) samples. input_ready is combinational off
    // registered state, which only moves on a posedge -- and the only posedge
    // between here and (3) is (3) itself -- so this value is stable into (3).
    bool willTransfer = (top_->input_valid && top_->input_ready);

    // (2) Falling edge (completes the 5 ns high phase).
    sim_time_ns_ += 4;
    top_->f_clk = 0;
    evalAndDump();

    // (3) Rising edge (completes the 5 ns low phase). Registers capture the
    //     inputs driven before this tick.
    sim_time_ns_ += 5;
    top_->f_clk = 1;
    evalAndDump();

    cycle_count_++;
    if (tick_hook_) {
        tick_hook_(*top_, cycle_count_);
    }
    return willTransfer;
}

void SharmonyDriver::tick(unsigned n) {
    for (unsigned i = 0; i < n; i++) tick();
}

void SharmonyDriver::reset(int cycles) {
    top_->resetn = 0;
    top_->start       = 0;
    top_->zeroize     = 0;
    top_->state_load  = 0;
    top_->state_save  = 0;
    top_->state_cache = 0;
    top_->input_data  = 0;
    top_->input_valid = 0;
    top_->input_bytes = 0;
    top_->input_final = 0;
    for (int i = 0; i < cycles; i++) tick();
    top_->resetn = 1;
    tick(); tick();   // 2-cycle settling
}

//-------------------------------------------------------------------------------------
//  Control
//-------------------------------------------------------------------------------------
void SharmonyDriver::setMode(Mode m) {
    top_->mode = static_cast<uint8_t>(m);
    top_->eval();
}

// Midstate caching qualifiers. Sampled with `start` (held until the op ends).
void SharmonyDriver::setStateLoad(bool assert_high) {
    top_->state_load = assert_high ? 1 : 0;
    top_->eval();
}

void SharmonyDriver::setStateSave(bool assert_high) {
    top_->state_save = assert_high ? 1 : 0;
    top_->eval();
}

void SharmonyDriver::setStateCache(bool assert_high) {
    top_->state_cache = assert_high ? 1 : 0;
    top_->eval();
}

void SharmonyDriver::pulseStart(unsigned timeoutCycles) {
    for (unsigned i = 0; i < timeoutCycles; i++) {
        tick();                       // posedge first, then check busy

        if (!top_->busy) {
            // Post-edge stimulus placement (same convention as tick() uses for
            // every other input): start rises just after a posedge, is stable
            // with a full setup window into the next posedge (which samples
            // it), and falls just after that sampling edge. Unlike the
            // rising-edge-coincident style, this leaves the VCD unambiguous:
            // busy's response lands one edge AFTER start's rise, not on the
            // same timestamp.
            top_->start = 1;
            tick();                   // posedge: DUT samples start=1
            top_->start = 0;
            top_->eval();
            tick();                   // settle cycle before the caller
                                      // starts driving input_valid
            return;
        }
    }

    throw TimeoutError("pulseStart: busy never deasserted within timeout");
}

//-------------------------------------------------------------------------------------
//  Input streaming
//-------------------------------------------------------------------------------------
void SharmonyDriver::sendBeat(uint64_t data, uint8_t bytes, uint8_t final_bits,
                               unsigned timeoutCycles) {
    top_->input_data  = data;
    top_->input_valid = 1;
    top_->input_bytes = bytes;
    top_->input_final = final_bits;
    top_->eval();

    for (unsigned i = 0; i < timeoutCycles; i++) {
        if (tick()) {
            // Beat accepted. LEAVE input_valid asserted and keep the data
            // fields at their current values - the next sendBeat will
            // overwrite them, or endMsg() will explicitly deassert.
            //
            // Earlier revisions of this driver deasserted valid here as
            // a "safety" measure. That caused the DUT to see valid drop
            // for one combinational delta between every pair of beats,
            // which works for some streaming patterns but breaks others
            // (notably asymmetric duet streams where one lane is already
            // finalized while the other is still pumping data).
            return;
        }
    }
    throw TimeoutError("sendBeat: input_ready never asserted within timeout");
}

void SharmonyDriver::endMsg() {
    top_->input_valid = 0;
    top_->input_data  = 0;
    top_->input_bytes = 0;
    top_->input_final = 0;
    top_->eval();
}

// Pack bytes into a 64-bit beat, MSB-first.
// e.g. bytes={0x61,0x62,0x63} -> 0x6162630000000000 with byte count 3.
static uint64_t packBeatMSBFirst(const uint8_t* p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        v |= (static_cast<uint64_t>(p[i]) << (56 - 8 * static_cast<int>(i)));
    }
    return v;
}

void SharmonyDriver::sendMessageNative(const std::vector<uint8_t>& msg,
                                        unsigned timeoutCycles) {
    if (msg.empty()) {
        // One beat, zero bytes, final.
        sendBeat(0, 0, 0b11, timeoutCycles);
        return;
    }

    size_t off = 0;
    while (off < msg.size()) {
        size_t remain = msg.size() - off;
        size_t take = remain >= 8 ? 8 : remain;
        bool   last = (off + take == msg.size());

        uint64_t beat = packBeatMSBFirst(msg.data() + off, take);
        uint8_t  bytes = static_cast<uint8_t>(take);
        uint8_t  fin   = last ? 0b11 : 0b00;

        sendBeat(beat, bytes, fin, timeoutCycles);
        off += take;
    }
}

//-------------------------------------------------------------------------------------
//  Duet streaming (SHA-224/256 duet build)
//-------------------------------------------------------------------------------------
void SharmonyDriver::sendBeatDuet(uint32_t hi_data, uint8_t hi_bytes, uint8_t hi_final,
                                   uint32_t lo_data, uint8_t lo_bytes, uint8_t lo_final,
                                   unsigned timeoutCycles) {
    uint64_t data = (static_cast<uint64_t>(hi_data) << 32)
                  | static_cast<uint64_t>(lo_data);
    uint8_t bytes = static_cast<uint8_t>(((hi_bytes & 0x7) << 3)
                                       |  (lo_bytes & 0x7));
    uint8_t fin   = static_cast<uint8_t>(((hi_final & 1) << 1)
                                       |  (lo_final & 1));
    sendBeat(data, bytes, fin, timeoutCycles);
}

// Pack up to 4 bytes into a 32-bit lane, MSB-first.
// e.g. {0x61,0x62,0x63} -> 0x61626300 with bytes=3.
static uint32_t packLaneMSBFirst(const uint8_t* p, size_t n) {
    uint32_t v = 0;
    for (size_t i = 0; i < n && i < 4; i++) {
        v |= (static_cast<uint32_t>(p[i]) << (24 - 8 * static_cast<int>(i)));
    }
    return v;
}

void SharmonyDriver::sendMessageDuetMirror(const std::vector<uint8_t>& msg,
                                            unsigned timeoutCycles) {
    if (msg.empty()) {
        // Terminal empty beat: both lanes signal "no bytes, final".
        sendBeatDuet(0, 0, 1, 0, 0, 1, timeoutCycles);
        return;
    }

    size_t off = 0;
    while (off < msg.size()) {
        size_t remain = msg.size() - off;
        size_t take = remain >= 4 ? 4 : remain;
        bool   last = (off + take == msg.size());

        uint32_t lane       = packLaneMSBFirst(msg.data() + off, take);
        uint8_t  lane_bytes = static_cast<uint8_t>(take);
        uint8_t  lane_final = last ? 1 : 0;

        // hi and lo carry identical data, len, and final flag (mirror mode).
        sendBeatDuet(lane, lane_bytes, lane_final,
                     lane, lane_bytes, lane_final,
                     timeoutCycles);
        off += take;
    }
}

// Drives both lanes of a duet message stream in lockstep. Each beat carries
// up to 4 bytes per lane. Once a lane signals final, it goes IDLE on
// subsequent beats (data=0, bytes=0, final=0). The loop terminates when
// both lanes have finalized.
void SharmonyDriver::sendMessagesDuet(const std::vector<uint8_t>& msg_hi,
                                       const std::vector<uint8_t>& msg_lo,
                                       unsigned timeoutCycles) {
    const size_t hi_n = msg_hi.size();
    const size_t lo_n = msg_lo.size();

    // Both empty -> single terminal beat with both finals asserted.
    if (hi_n == 0 && lo_n == 0) {
        sendBeatDuet(0, 0, 1, 0, 0, 1, timeoutCycles);
        return;
    }

    size_t hi_pos = 0, lo_pos = 0;
    bool   hi_finalized = false, lo_finalized = false;

    while (!(hi_finalized && lo_finalized)) {
        const size_t hi_remaining = hi_n - hi_pos;
        const size_t lo_remaining = lo_n - lo_pos;

        const size_t hi_bytes_this = hi_finalized
                                       ? 0
                                       : (hi_remaining < 4 ? hi_remaining : 4);
        const size_t lo_bytes_this = lo_finalized
                                       ? 0
                                       : (lo_remaining < 4 ? lo_remaining : 4);

        const bool hi_final_this = !hi_finalized && (hi_pos + hi_bytes_this == hi_n);
        const bool lo_final_this = !lo_finalized && (lo_pos + lo_bytes_this == lo_n);

        const uint32_t hi_word = packLaneMSBFirst(msg_hi.data() + hi_pos, hi_bytes_this);
        const uint32_t lo_word = packLaneMSBFirst(msg_lo.data() + lo_pos, lo_bytes_this);

        sendBeatDuet(hi_word, static_cast<uint8_t>(hi_bytes_this),
                     static_cast<uint8_t>(hi_final_this ? 1 : 0),
                     lo_word, static_cast<uint8_t>(lo_bytes_this),
                     static_cast<uint8_t>(lo_final_this ? 1 : 0),
                     timeoutCycles);

        hi_pos += hi_bytes_this;
        lo_pos += lo_bytes_this;
        if (hi_final_this) hi_finalized = true;
        if (lo_final_this) lo_finalized = true;
    }
}

//-------------------------------------------------------------------------------------
//  Output collection
//-------------------------------------------------------------------------------------
std::vector<uint64_t> SharmonyDriver::collectBeats(size_t n,
                                                    unsigned timeoutPerBeat) {
    std::vector<uint64_t> out;
    out.reserve(n);
    unsigned waited = 0;
    while (out.size() < n) {
        tick();
        if (top_->output_valid) {
            out.push_back(top_->output_data);
            waited = 0;
        } else {
            if (++waited > timeoutPerBeat) {
                std::ostringstream os;
                os << "collectBeats: timeout after beat " << out.size()
                   << " of " << n;
                throw TimeoutError(os.str());
            }
        }
    }
    return out;
}

//-------------------------------------------------------------------------------------
//  Non-throwing variants (used by scenario / error / reset tests).
//-------------------------------------------------------------------------------------
bool SharmonyDriver::tryPulseStart(unsigned timeoutCycles) {
    for (unsigned i = 0; i < timeoutCycles; i++) {
        tick();

        if (!top_->busy) {
            // Post-edge placement, same as pulseStart().
            top_->start = 1;
            tick();
            top_->start = 0;
            top_->eval();
            tick();
            return true;
        }
    }

    return false;
}

bool SharmonyDriver::trySendBeat(uint64_t data, uint8_t bytes,
                                  uint8_t final_bits, unsigned timeoutCycles) {
    top_->input_data  = data;
    top_->input_valid = 1;
    top_->input_bytes = bytes;
    top_->input_final = final_bits;
    top_->eval();
    for (unsigned i = 0; i < timeoutCycles; i++) {
        if (tick()) return true;
    }
    return false;
}

bool SharmonyDriver::trySendBeatDuet(uint32_t hi_data, uint8_t hi_bytes, uint8_t hi_final,
                                      uint32_t lo_data, uint8_t lo_bytes, uint8_t lo_final,
                                      unsigned timeoutCycles) {
    uint64_t data = (static_cast<uint64_t>(hi_data) << 32) | lo_data;
    uint8_t  bytes = static_cast<uint8_t>(((hi_bytes & 0x7) << 3) | (lo_bytes & 0x7));
    uint8_t  fin   = static_cast<uint8_t>(((hi_final & 1) << 1) | (lo_final & 1));
    return trySendBeat(data, bytes, fin, timeoutCycles);
}

bool SharmonyDriver::waitOutputValid(unsigned timeoutCycles) {
    for (unsigned i = 0; i < timeoutCycles; i++) {
        tick();
        if (top_->output_valid) return true;
    }
    return false;
}

std::pair<bool, std::vector<uint64_t>>
SharmonyDriver::tryCollectBeats(size_t n, unsigned timeoutPerBeat) {
    std::vector<uint64_t> out;
    out.reserve(n);
    unsigned waited = 0;
    while (out.size() < n) {
        tick();
        if (top_->output_valid) {
            out.push_back(top_->output_data);
            waited = 0;
        } else {
            if (++waited > timeoutPerBeat) return {false, out};
        }
    }
    return {true, out};
}

void SharmonyDriver::forceIdleInputs() {
    top_->start       = 0;
    top_->zeroize     = 0;
    top_->input_data  = 0;
    top_->input_valid = 0;
    top_->input_bytes = 0;
    top_->input_final = 0;
    top_->eval();
    tick();
}

void SharmonyDriver::setZeroize(bool assert_high) {
    top_->zeroize = assert_high ? 1 : 0;
    top_->eval();
}

void SharmonyDriver::setOutReady(bool assert_high) {
    top_->output_ready = assert_high ? 1 : 0;
    top_->eval();
}

//-------------------------------------------------------------------------------------
//  Probes
//-------------------------------------------------------------------------------------
bool SharmonyDriver::outputValid() const { return top_->output_valid; }
bool SharmonyDriver::inputReady() const  { return top_->input_ready; }
bool SharmonyDriver::busy() const { return top_->busy; }
bool SharmonyDriver::acceptStart() const { return !top_->busy; }
uint64_t SharmonyDriver::outputData() const { return top_->output_data; }

bool SharmonyDriver::sensitiveRegsZero(std::string* firstNonzero) const {
    auto* r = top_->rootp;
#define SH_CORE(x) r->sharmony_verilator_wrapper__DOT__dut__DOT__core_inst__DOT__##x
#define SH_PAD(x)  r->sharmony_verilator_wrapper__DOT__dut__DOT__pad_inst__DOT__##x
    auto fail = [&](const std::string& name) {
        if (firstNonzero) *firstNonzero = name;
        return false;
    };
    for (int i = 0; i < 25; ++i)
        if (SH_CORE(R_q)[i] != 0ULL) return fail("R_q[" + std::to_string(i) + "]");
    for (int i = 0; i < 8; ++i)
        if (SH_CORE(H_q)[i] != 0ULL) return fail("H_q[" + std::to_string(i) + "]");
    if (SH_CORE(u_data)        != 0ULL) return fail("u_data");
    if (SH_CORE(output_data_b) != 0ULL) return fail("output_data_b");
    if (SH_CORE(skid_data)     != 0ULL) return fail("skid_data");
    if (SH_PAD(in_data_q)      != 0ULL) return fail("in_data_q");
    if (SH_PAD(in_bytes_q)     != 0)    return fail("in_bytes_q");
#undef SH_CORE
#undef SH_PAD
    return true;
}

//-------------------------------------------------------------------------------------
//  Utilities
//-------------------------------------------------------------------------------------
std::vector<uint8_t> SharmonyDriver::beatsToBytes(
        const std::vector<uint64_t>& beats, size_t n_bytes) {
    std::vector<uint8_t> out;
    out.reserve(n_bytes);
    for (size_t i = 0; i < beats.size() && out.size() < n_bytes; i++) {
        uint64_t v = beats[i];
        for (int j = 0; j < 8 && out.size() < n_bytes; j++) {
            out.push_back(static_cast<uint8_t>((v >> (56 - 8 * j)) & 0xFF));
        }
    }
    return out;
}

std::vector<uint8_t> SharmonyDriver::beatsToLoLaneBytes(
        const std::vector<uint64_t>& beats, size_t n_bytes) {
    std::vector<uint8_t> out;
    out.reserve(n_bytes);
    for (size_t i = 0; i < beats.size() && out.size() < n_bytes; i++) {
        uint32_t lo = static_cast<uint32_t>(beats[i] & 0xFFFFFFFFULL);
        for (int j = 0; j < 4 && out.size() < n_bytes; j++) {
            out.push_back(static_cast<uint8_t>((lo >> (24 - 8 * j)) & 0xFF));
        }
    }
    return out;
}

std::vector<uint8_t> SharmonyDriver::beatsToHiLaneBytes(
        const std::vector<uint64_t>& beats, size_t n_bytes) {
    std::vector<uint8_t> out;
    out.reserve(n_bytes);
    for (size_t i = 0; i < beats.size() && out.size() < n_bytes; i++) {
        uint32_t hi = static_cast<uint32_t>((beats[i] >> 32) & 0xFFFFFFFFULL);
        for (int j = 0; j < 4 && out.size() < n_bytes; j++) {
            out.push_back(static_cast<uint8_t>((hi >> (24 - 8 * j)) & 0xFF));
        }
    }
    return out;
}

std::string SharmonyDriver::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (uint8_t b : bytes) os << std::setw(2) << static_cast<int>(b);
    return os.str();
}

}  // namespace sharmony
