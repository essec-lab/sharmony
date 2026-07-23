///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Implementation-performance characterization for the Verilator C++ flow.
//
// Measurements taken per transaction, all in parallel from one tick hook:
//   1. FSM-state counts, sampled from sharmony_core.core_fsm_q (public_flat_rd).
//      Diagnostic only now (component breakdown / IDLE-bubble detection).
//   2. busy-cycle count, sampled from the top-level `busy` output
//      (busy = zeroize_active || !pad_idle || !core_idle): full pad+core window.
//   3. Event-anchored cycle indices, latched on signal transitions:
//        - first observed start==1
//        - busy rise / busy LAST-high
//        - first / last non-IDLE core_fsm_q
//      These give the END-TO-END latency (external start -> busy deasserts) that
//      now drives the Lat columns, plus a pure core window and a self-check of
//      the legacy FSM-sum. See the notes at the bottom.
//
// LATENCY BASIS (changed): the Lat 1blk/2blk/64blk columns now report the
// END-TO-END transaction time = external start asserted .. busy deasserts for
// good (== the Start->Done number). This includes the REG_IO start_q delay, the
// pad lead-in, every core cycle, any inter-block IDLE bubble, and the pad drain
// after the core returns to IDLE - none of which the old FSM-state-sum counted.
// The legacy FSM sum is retained as a diagnostic (per-row breakdown at VERBOSE=1).
//
// SHA-224/256 are DUET modes (two independent 32-bit lanes, one shared FSM,
// run in lockstep). They produce TWO rows each:
//   * "(1-lane)" : lo lane carries data, hi lane padded with zeros. Useful
//                  stride = 64 B/block (one lane). Hi-lane work is wasted.
//   * "(duet)"   : both lanes carry data. Useful stride = 128 B/block-pair.
// Because the FSM runs both lanes in lockstep, the CYCLE counts of the two
// rows are identical by construction; only the throughput denominator differs
// (single-lane throughput == half of duet throughput). Both rows therefore show
// identical Lat columns by construction.
//
///////////////////////////////////////////////////////////////////////////////////////

#include "../SharmonyDriver.hpp"
#include "../TestRegistry.hpp"

#include "Vsharmony_verilator_wrapper.h"
#include "Vsharmony_verilator_wrapper___024root.h"

#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace sharmony {
namespace {

// essec_sharmony_pkg::core_fsm_e values. Keep in sync with
// hw/sharmony/essec_sharmony_pkg.sv.
enum CoreFsmValue : uint8_t {
    CORE_IDLE       = 0,
    CORE_INIT       = 1,
    CORE_ROUNDS     = 2,
    CORE_NEXT       = 3,
    CORE_WAIT       = 4,
    CORE_ZEROIZE    = 5,
    CORE_ABSORB     = 6,
    CORE_OUTPUT     = 7,
    CORE_SHA3_INIT  = 8,
    CORE_OUTPUT_XOF = 9,
    CORE_FSM_COUNT  = 10
};

static const char* fsmName(uint8_t s) {
    switch (s) {
        case CORE_IDLE:      return "IDLE";
        case CORE_INIT:      return "INIT";
        case CORE_ROUNDS:    return "ROUNDS";
        case CORE_NEXT:      return "NEXT";
        case CORE_WAIT:      return "WAIT";
        case CORE_ZEROIZE:   return "ZEROIZE";
        case CORE_ABSORB:    return "ABSORB";
        case CORE_OUTPUT:     return "OUTPUT";
        case CORE_SHA3_INIT:  return "SHA3_INIT";
        case CORE_OUTPUT_XOF: return "OUTPUT_XOF";
        default:              return "INVALID_STATE";
    }
}

// Internal signal: read via the flattened root member (public_flat_rd).
static uint8_t readCoreFsm(const Vsharmony_verilator_wrapper& top) {
    return static_cast<uint8_t>(
        top.rootp->sharmony_verilator_wrapper__DOT__dut__DOT__core_inst__DOT__core_fsm_q);
}

// Top-level OUTPUT port: Verilator exposes top-level ports as direct members of
// the model, so read busy straight off `top`.
static bool readBusy(const Vsharmony_verilator_wrapper& top) {
    return static_cast<bool>(top.busy);
}

// Top-level INPUT port `start` (direct member of the wrapped model).
// This is the EXTERNAL start (pre-REG_IO register). The start->core gap measured
// below therefore includes the REG_IO start_q delay + pad lead-in, which is
// exactly the front-end latency the old FSM-sum method omitted.
static bool readStart(const Vsharmony_verilator_wrapper& top) {
    return static_cast<bool>(top.start);
}

struct FsmCounts {
    uint64_t state[CORE_FSM_COUNT] = {};
    uint64_t unknown = 0;
    uint64_t total = 0;

    void sample(uint8_t s) {
        total++;
        if (s < CORE_FSM_COUNT) state[s]++;
        else unknown++;
    }
};

// Cycle indices latched on signal transitions within the armed window.
struct EventCycles {
    bool     have_start = false;
    bool     have_busy  = false;
    bool     have_core  = false;
    uint64_t start_cycle = 0;   // first tick start==1
    uint64_t busy_rise   = 0;   // first tick busy==1
    uint64_t busy_last   = 0;   // LAST tick busy==1  (robust end-of-transaction anchor)
    uint64_t core_first  = 0;   // first tick core_fsm != IDLE
    uint64_t core_last   = 0;   // last  tick core_fsm != IDLE
};

// Samples the core FSM state, the top-level busy signal, and the event cycles
// each tick while armed.
class TxnMonitor {
public:
    void reset() {
        counts_ = {};
        busy_cycles_ = 0;
        armed_ = false;
        ev_ = {};
        idx_ = 0;
    }
    void arm()    { armed_ = true; }
    void disarm() { armed_ = false; }

    // The hook's uint64_t argument (the driver's cycle count) is ignored:
    // idx_ increments exactly once per sample (== once per cycle, since the
    // hook fires once per tick), so all event timestamps are true cycle
    // indices regardless of the arg.
    void sample(const Vsharmony_verilator_wrapper& top, uint64_t /*cyc_unused*/) {
        if (!armed_) return;
        const uint64_t cyc  = idx_++;
        const uint8_t  fsm   = readCoreFsm(top);
        const bool     busy  = readBusy(top);
        const bool     start = readStart(top);

        counts_.sample(fsm);
        if (busy) busy_cycles_++;

        if (start && !ev_.have_start) {
            ev_.have_start = true;
            ev_.start_cycle = cyc;
        }
        if (busy) {
            if (!ev_.have_busy) { ev_.have_busy = true; ev_.busy_rise = cyc; }
            ev_.busy_last = cyc;            // keep advancing -> captures the FINAL fall
        }
        if (fsm != CORE_IDLE) {
            if (!ev_.have_core) { ev_.have_core = true; ev_.core_first = cyc; }
            ev_.core_last = cyc;
        }
    }

    const FsmCounts&   counts() const { return counts_; }
    uint64_t           busyCycles() const { return busy_cycles_; }
    const EventCycles& events() const { return ev_; }

private:
    bool        armed_ = false;
    FsmCounts   counts_;
    uint64_t    busy_cycles_ = 0;
    uint64_t    idx_ = 0;   // monotonic per-cycle sample index (1 per tick)
    EventCycles ev_;
};

struct ModeSpec {
    Mode mode;
    const char* name;
    int digest_bits;               // digest size in bits; -1 = variable (XOF)
    int rate_block_bytes;          // compression-block / rate size (one lane)
    int one_block_payload_bytes;   // max payload in one internal block (one lane)
    int measure_block_bytes;       // long-message measurement stride (native)
    // duet-only (SHA-224/256); 0 for non-duet modes:
    int  lane_block_bytes;         // per-lane compression block (64 for SHA-256)
    int  lane_one_block_payload;   // per-lane max single-block payload (55)
    bool is_duet;
};

static const std::vector<ModeSpec>& modeSpecs() {
    static const std::vector<ModeSpec> specs = {
        //                          dig  rate 1blk meas | laneB lane1blk duet
        {Mode::SHA2_224,     "SHA-224",     224,  64,  55, 128,   64, 55, true },
        {Mode::SHA2_256,     "SHA-256",     256,  64,  55, 128,   64, 55, true },
        {Mode::SHA2_384,     "SHA-384",     384, 128, 111, 128,    0,  0, false},
        {Mode::SHA2_512,     "SHA-512",     512, 128, 111, 128,    0,  0, false},
        {Mode::SHA2_512_224, "SHA-512/224", 224, 128, 111, 128,    0,  0, false},
        {Mode::SHA2_512_256, "SHA-512/256", 256, 128, 111, 128,    0,  0, false},

        {Mode::SHA3_224,     "SHA3-224",    224, 144, 143, 144,    0,  0, false},
        {Mode::SHA3_256,     "SHA3-256",    256, 136, 135, 136,    0,  0, false},
        {Mode::SHA3_384,     "SHA3-384",    384, 104, 103, 104,    0,  0, false},
        {Mode::SHA3_512,     "SHA3-512",    512,  72,  71,  72,    0,  0, false},
        {Mode::SHAKE128,     "SHAKE128",     -1, 168, 167, 168,    0,  0, false},
        {Mode::SHAKE256,     "SHAKE256",     -1, 136, 135, 136,    0,  0, false},
    };
    return specs;
}

static std::vector<uint8_t> makeMessage(size_t bytes, unsigned seed = 17u) {
    std::vector<uint8_t> msg(bytes);
    for (size_t i = 0; i < msg.size(); ++i) {
        msg[i] = static_cast<uint8_t>((seed + 131u * static_cast<unsigned>(i)) & 0xffu);
    }
    return msg;
}

struct Measurement {
    FsmCounts   fsm;
    uint64_t    busy_cycles = 0;
    EventCycles ev;
};

static bool isShakeMode(Mode mode) {
    return mode == Mode::SHAKE128 || mode == Mode::SHAKE256;
}

static bool isSha3Family(Mode mode) {
    switch (mode) {
        case Mode::SHA3_224: case Mode::SHA3_256: case Mode::SHA3_384:
        case Mode::SHA3_512: case Mode::SHAKE128: case Mode::SHAKE256:
            return true;
        default:
            return false;
    }
}

// Drive extra ticks (still armed) until the engine has SETTLED back to idle, so
// ev.busy_last captures the FINAL busy fall (robust to a mid-transaction busy
// bubble). We stop once busy has read low for several consecutive cycles. For
// XOF, drop out_ready first: that is the documented squeeze-STOP that lets the
// core leave CORE_OUTPUT_XOF.
static void drainToIdle(SharmonyDriver& drv, Mode mode, int max_ticks = 256) {
    const bool xof = isShakeMode(mode);
    if (xof) drv.setOutReady(false);
    int low_run = 0;
    for (int i = 0; i < max_ticks && low_run < 4; ++i) {
        drv.tick();
        low_run = readBusy(*drv.model()) ? 0 : (low_run + 1);
    }
    if (xof) drv.setOutReady(true);
}

// Non-duet path: native single-stream feed.
static Measurement measureMessage(SharmonyDriver& drv,
                                  const ModeSpec& spec,
                                  size_t msg_bytes) {
    TxnMonitor mon;

    drv.reset();
    drv.setMode(spec.mode);

    drv.setTickHook([&](const Vsharmony_verilator_wrapper& top, uint64_t cyc) {
        mon.sample(top, cyc);
    });

    const auto msg = makeMessage(msg_bytes);

    mon.reset();
    mon.arm();
    drv.pulseStart();
    drv.sendMessageNative(msg);
    drv.endMsg();
    (void)drv.collectBeats(static_cast<size_t>(digestBeatsFor(spec.mode)));
    drainToIdle(drv, spec.mode);

    mon.disarm();
    drv.clearTickHook();

    Measurement m;
    m.fsm = mon.counts();
    m.busy_cycles = mon.busyCycles();
    m.ev = mon.events();
    return m;
}

// Duet path: feed both lanes with EQUAL-length payloads (symmetric -> identical
// cycles regardless of hi-lane content). hi_real selects whether the hi lane
// carries real data (duet row) or zeros (single-lane row).
static Measurement measureDuet(SharmonyDriver& drv,
                               const ModeSpec& spec,
                               size_t per_lane_bytes,
                               bool hi_real) {
    TxnMonitor mon;

    drv.reset();
    drv.setMode(spec.mode);

    drv.setTickHook([&](const Vsharmony_verilator_wrapper& top, uint64_t cyc) {
        mon.sample(top, cyc);
    });

    const std::vector<uint8_t> lo = makeMessage(per_lane_bytes, /*seed=*/17u);
    const std::vector<uint8_t> hi =
        hi_real ? makeMessage(per_lane_bytes, /*seed=*/97u)
                : std::vector<uint8_t>(per_lane_bytes, 0u);

    mon.reset();
    mon.arm();
    drv.pulseStart();
    drv.sendMessagesDuet(hi, lo);
    (void)drv.collectBeats(static_cast<size_t>(digestBeatsFor(spec.mode)));
    drainToIdle(drv, spec.mode);

    mon.disarm();
    drv.clearTickHook();

    Measurement m;
    m.fsm = mon.counts();
    m.busy_cycles = mon.busyCycles();
    m.ev = mon.events();
    return m;
}

static long long roundToInt(double v) {
    return static_cast<long long>(std::llround(v));
}

static uint64_t setupCycles(const ModeSpec& spec, const Measurement& m) {
    uint64_t cycles = isSha3Family(spec.mode) ? m.fsm.state[CORE_SHA3_INIT]
                                              : m.fsm.state[CORE_INIT];
    if (isSha3Family(spec.mode)) {
        cycles += m.fsm.state[CORE_ABSORB];
        if (!isShakeMode(spec.mode)) cycles += m.fsm.state[CORE_OUTPUT];
    } else {
        cycles += m.fsm.state[CORE_OUTPUT];
    }
    return cycles;
}

// Legacy diagnostic: sum of all non-IDLE core FSM cycles. Omits front-end, pad
// drain, and IDLE bubbles - kept ONLY for the breakdown / match check, no longer
// used for the Lat columns.
static uint64_t measuredLatencyCycles(const Measurement& m) {
    uint64_t cycles = 0;
    for (int s = 0; s < CORE_FSM_COUNT; ++s) {
        if (s == CORE_IDLE) continue;
        cycles += m.fsm.state[s];
    }
    return cycles;
}

//-------------------------------------------------------------------------------------
//  Event-anchored derivations
//-------------------------------------------------------------------------------------

// END-TO-END transaction latency: external start asserted .. busy deasserts for
// good. busy_last+1 is the cycle busy is finally low, so this is robust to any
// mid-transaction busy bubble. THIS is what the Lat columns report.
static uint64_t endToEndCycles(const Measurement& m) {
    if (!m.ev.have_start || !m.ev.have_busy) return 0;
    return m.ev.busy_last + 1 - m.ev.start_cycle;
}
// Alias kept for the table/breakdown call sites (identical to endToEnd now).
static uint64_t startToDoneCycles(const Measurement& m) { return endToEndCycles(m); }

// Pure core window: first non-IDLE .. last non-IDLE, inclusive.
static uint64_t coreActiveCycles(const Measurement& m) {
    if (!m.ev.have_core) return 0;
    return m.ev.core_last - m.ev.core_first + 1;
}
// Front-end latency: external start asserted .. core leaves IDLE.
static uint64_t startToCoreCycles(const Measurement& m) {
    if (!m.ev.have_start || !m.ev.have_core) return 0;
    return m.ev.core_first - m.ev.start_cycle;
}
// Hardware active window: busy rise .. final busy fall.
static uint64_t busyWindowCycles(const Measurement& m) {
    if (!m.ev.have_busy) return 0;
    return m.ev.busy_last + 1 - m.ev.busy_rise;
}
// core-window vs FSM-sum: equal for a contiguous transaction; mismatch => the
// FSM bubbled through IDLE mid-transaction (the case the old method hid).
static bool coreWindowMatchesSum(const Measurement& m) {
    return coreActiveCycles(m) == measuredLatencyCycles(m);
}

static void printStateCount(uint8_t state, const Measurement& m,
                            bool force_print = false) {
    const uint64_t count = (state < CORE_FSM_COUNT) ? m.fsm.state[state] : 0;
    if (!force_print && count == 0) return;
    std::cout << "    " << std::setw(9) << fsmName(state) << " : " << count << "\n";
}

static bool isSha3VerboseState(uint8_t state) {
    switch (state) {
        case CORE_SHA3_INIT: case CORE_ABSORB: case CORE_ROUNDS: case CORE_OUTPUT:
            return true;
        default:
            return false;
    }
}

//-------------------------------------------------------------------------------------
//  Row model
//-------------------------------------------------------------------------------------

struct RowPlan {
    ModeSpec spec;
    const char* suffix;          // "", "(1-lane)", "(duet)"
    bool        duet_feed;       // use measureDuet (both lanes equal length)
    bool        hi_real;         // duet-both vs single-lane(hi zeros)
    int         rate_blk_bytes;  // table "Rate/Blk"
    int         useful_1blk;     // table "Useful 1blk"
    int         stride_bytes;    // throughput stride (useful bytes per block(-pair))
};

// Per-measurement physical payload (per lane for duet, native for non-duet).
struct PayloadPlan {
    size_t one;    // single internal block
    size_t two;    // one rate block (forces 2 internal blocks)
    size_t k32;    // 32 strides
    size_t k64;    // 64 strides
};

static PayloadPlan payloadPlan(const RowPlan& p) {
    if (p.duet_feed) {
        const size_t b   = static_cast<size_t>(p.spec.lane_block_bytes);        // 64
        const size_t one = static_cast<size_t>(p.spec.lane_one_block_payload);  // 55
        return {one, b, b * 32u, b * 64u};
    }
    const size_t mb  = static_cast<size_t>(p.spec.measure_block_bytes);
    const size_t one = static_cast<size_t>(p.spec.one_block_payload_bytes);
    return {one, mb, mb * 32u, mb * 64u};
}

static Measurement measureFor(SharmonyDriver& drv, const RowPlan& p, size_t bytes) {
    return p.duet_feed ? measureDuet(drv, p.spec, bytes, p.hi_real)
                       : measureMessage(drv, p.spec, bytes);
}

static std::string rowDisplayName(const RowPlan& p) {
    std::string s(p.spec.name);
    if (p.suffix && p.suffix[0]) { s += " "; s += p.suffix; }
    if (isShakeMode(p.spec.mode)) s += "*";
    return s;
}

static std::vector<RowPlan> buildRowPlans() {
    std::vector<RowPlan> plans;
    for (const auto& spec : modeSpecs()) {
        if (spec.is_duet) {
            plans.push_back(RowPlan{spec, "(1-lane)", /*duet*/true, /*hi_real*/false,
                                    spec.lane_block_bytes,           // 64
                                    spec.lane_one_block_payload,     // 55
                                    spec.lane_block_bytes});         // stride 64
            plans.push_back(RowPlan{spec, "(duet)", /*duet*/true, /*hi_real*/true,
                                    spec.lane_block_bytes * 2,       // 128
                                    spec.lane_one_block_payload * 2, // 110
                                    spec.lane_block_bytes * 2});     // stride 128
        } else {
            plans.push_back(RowPlan{spec, "", /*duet*/false, /*hi_real*/false,
                                    spec.rate_block_bytes,
                                    spec.one_block_payload_bytes,
                                    spec.measure_block_bytes});
        }
    }
    return plans;
}

struct Row {
    RowPlan     plan;
    Measurement one;
    Measurement two;
    Measurement thirtytwo;
    Measurement sixtyfour;
    uint64_t setup = 0;
    uint64_t lat1blk = 0;
    uint64_t lat2blk = 0;
    uint64_t lat64blk = 0;
    double   per_block = 0.0;
    double   mbps = 0.0;
    double   MBps = 0.0;
    // busy companions
    double   busy_per_block = 0.0;
};

static void printFsmBreakdown(const char* label, const RowPlan& p, const Measurement& m) {
    std::cout << "\n[performance] FSM breakdown " << rowDisplayName(p) << " " << label << "\n";
    std::cout << "  end-to-end (start->done) : " << startToDoneCycles(m)
              << "   <- Lat column basis\n";
    std::cout << "  latency cycles (FSM sum) : " << measuredLatencyCycles(m)
              << "   (diagnostic; omits front-end + drain + bubbles)\n";
    std::cout << "  core active (window)     : " << coreActiveCycles(m)
              << (coreWindowMatchesSum(m) ? "  [== FSM sum]" : "  [!= FSM sum: IDLE bubble]") << "\n";
    std::cout << "  start -> core            : " << startToCoreCycles(m) << "\n";
    std::cout << "  busy cycles / window     : " << m.busy_cycles
              << " / " << busyWindowCycles(m) << "\n";
    std::cout << "  state counts:\n";

    if (isSha3Family(p.spec.mode)) {
        printStateCount(CORE_SHA3_INIT, m);
        printStateCount(CORE_ABSORB, m);
        printStateCount(CORE_ROUNDS, m);
        printStateCount(CORE_OUTPUT, m);
        for (uint8_t s = 0; s < CORE_FSM_COUNT; ++s) {
            if (s == CORE_IDLE || isSha3VerboseState(s)) continue;
            printStateCount(s, m);
        }
        return;
    }
    for (uint8_t s = 0; s < CORE_FSM_COUNT; ++s) {
        if (s == CORE_IDLE) continue;
        printStateCount(s, m);
    }
}

static int run_performance(SharmonyDriver& drv, const TestOptions& opts) {
    double freq_mhz = opts.freq_mhz;
    if (!(freq_mhz > 0.0)) freq_mhz = 132.0;
    const double period_ns = 1000.0 / freq_mhz;

    const std::vector<RowPlan> plans = buildRowPlans();

    std::vector<Row> rows;
    rows.reserve(plans.size());

    try {
        for (const auto& plan : plans) {
            const PayloadPlan pp = payloadPlan(plan);
            Row row{plan};
            row.one       = measureFor(drv, plan, pp.one);
            row.two       = measureFor(drv, plan, pp.two);
            row.thirtytwo = measureFor(drv, plan, pp.k32);
            row.sixtyfour = measureFor(drv, plan, pp.k64);

            //-------------------------------------------------------------------------
            //  Lat columns: END-TO-END (start -> done), event-anchored
            //-------------------------------------------------------------------------
            row.setup    = setupCycles(plan.spec, row.one);   // FSM-component diagnostic
            row.lat1blk  = startToDoneCycles(row.one);
            row.lat2blk  = startToDoneCycles(row.two);
            const uint64_t lat32blk = startToDoneCycles(row.thirtytwo);
            row.lat64blk = startToDoneCycles(row.sixtyfour);

            // Per-block from the end-to-end DIFFERENCE: the fixed front-end +
            // pad drain are identical in lat32 and lat64, so they cancel,
            // leaving the steady-state core cost per compression block (per lane).
            row.per_block = static_cast<double>(row.lat64blk - lat32blk) / 32.0;

            row.mbps = (8.0 * static_cast<double>(plan.stride_bytes) * freq_mhz) / row.per_block;
            row.MBps = row.mbps / 8.0;

            //-------------------------------------------------------------------------
            //  busy companions
            //-------------------------------------------------------------------------
            row.busy_per_block = static_cast<double>(row.sixtyfour.busy_cycles
                                                     - row.thirtytwo.busy_cycles) / 32.0;

            if (opts.verbosity >= 1) {
                printFsmBreakdown("1blk",  plan, row.one);
                printFsmBreakdown("2blk",  plan, row.two);
                printFsmBreakdown("32blk", plan, row.thirtytwo);
                printFsmBreakdown("64blk", plan, row.sixtyfour);

                std::cout << "\n[performance] busy-cycle totals " << rowDisplayName(plan) << "\n";
                std::cout << "  1blk  : " << row.one.busy_cycles << " cycles\n";
                std::cout << "  2blk  : " << row.two.busy_cycles << " cycles\n";
                std::cout << "  32blk : " << row.thirtytwo.busy_cycles << " cycles\n";
                std::cout << "  64blk : " << row.sixtyfour.busy_cycles << " cycles\n";
                std::cout << "  busy per-stride : " << std::fixed << std::setprecision(2)
                          << row.busy_per_block << " cycles"
                          << "   (E2E per-stride = " << row.per_block << ")\n";
            }

            rows.push_back(row);
        }
    } catch (const std::exception& e) {
        drv.clearTickHook();
        std::cerr << "[performance] measurement failed: " << e.what() << "\n";
        return 1;
    }

    //---------------------------------------------------------------------------------
    //  Main table
    //---------------------------------------------------------------------------------
    std::cout << "\n";
    std::cout << "======================================================================================\n";
    std::cout << "  Sharmony Performance Characterization  (f_clk = "
              << std::fixed << std::setprecision(0) << freq_mhz
              << " MHz, T = " << std::setprecision(2) << period_ns << " ns)\n";
    std::cout << "  Latency[cycles] = Fixed + Nblk x PerBlk        Throughput = steady state (long msg)\n";
    std::cout << "======================================================================================\n";
    std::cout << "| Mode         | Block | Digest |         Latency [cycles]         |  Throughput  |\n";
    std::cout << "|              |  [B]  | [bits] | Fixed | PerBlk |  1blk  |  64blk |  Mbps | MB/s |\n";
    std::cout << "|--------------|-------|--------|-------|--------|--------|--------|-------|------|\n";

    const char* kDitto = "\"";
    for (const auto& r : rows) {
        const bool duet_sub = std::string(r.plan.suffix) == "(duet)";

        std::string name;
        if (duet_sub) {
            name = "  +duet";
        } else {
            name = r.plan.spec.name;
            if (isShakeMode(r.plan.spec.mode)) name += " *";
        }
        const std::string digest =
            r.plan.spec.digest_bits < 0 ? std::string("var")
                                        : std::to_string(r.plan.spec.digest_bits);
        const long long fixed = static_cast<long long>(r.lat1blk) - roundToInt(r.per_block);

        std::cout << "| " << std::left << std::setw(12) << name << std::right
                  << " | " << std::setw(5) << r.plan.rate_blk_bytes
                  << " | " << std::setw(6) << (duet_sub ? std::string(kDitto) : digest);
        if (duet_sub) {
            // Cycle columns are identical to the base row (one FSM, lockstep lanes).
            std::cout << " | " << std::setw(5) << kDitto
                      << " | " << std::setw(6) << kDitto
                      << " | " << std::setw(6) << kDitto
                      << " | " << std::setw(6) << kDitto;
        } else {
            std::cout << " | " << std::setw(5) << fixed
                      << " | " << std::setw(6) << roundToInt(r.per_block)
                      << " | " << std::setw(6) << r.lat1blk
                      << " | " << std::setw(6) << r.lat64blk;
        }
        std::cout << " | " << std::setw(5) << roundToInt(r.mbps)
                  << " | " << std::setw(4) << roundToInt(r.MBps)
                  << " |\n";
    }
    std::cout << "======================================================================================\n";

    // ---- Cycle-phase breakdown (physical FSM phases behind Fixed / PerBlk) ----
    // Derived per row from the 1-block and 2-block measurements, so it stays exact:
    //   PerBlk = Rounds + Absorb + Gap ;  Fixed = Lead + Init + Tail - Gap
    // SHA-2 has an inter-block Gap (NEXT); SHA-3 absorbs a block instead (Absorb).
    std::cout << "\n";
    std::cout << "  Cycle-phase breakdown (physical FSM phases; f_clk-independent)\n";
    std::cout << "  once/op: Lead + Init + Tail    per-block: Rounds + Absorb (SHA-3) or Gap between blocks (SHA-2)\n";
    std::cout << "| Mode         | Lead | Init | Absorb | Rounds |  Gap | Tail | Fixed | PerBlk |\n";
    std::cout << "|              |  x1  |  x1  |  /blk  |  /blk  | xN-1 |  x1  |       |        |\n";
    std::cout << "|--------------|------|------|--------|--------|------|------|-------|--------|\n";
    for (const auto& r : rows) {
        if (std::string(r.plan.suffix) == "(duet)") continue;  // identical cycles to base row
        const bool sha3 = isSha3Family(r.plan.spec.mode);

        std::string name = r.plan.spec.name;
        if (isShakeMode(r.plan.spec.mode)) name += " *";

        const long long lead   = static_cast<long long>(startToCoreCycles(r.one));
        const long long init   = sha3 ? r.one.fsm.state[CORE_SHA3_INIT]
                                      : r.one.fsm.state[CORE_INIT];
        const long long absorb = static_cast<long long>(r.two.fsm.state[CORE_ABSORB])
                                 - r.one.fsm.state[CORE_ABSORB];   // per block (0 for SHA-2)
        const long long rounds = static_cast<long long>(r.two.fsm.state[CORE_ROUNDS])
                                 - r.one.fsm.state[CORE_ROUNDS];   // per block
        const long long gap    = static_cast<long long>(r.two.fsm.state[CORE_NEXT])
                                 - r.one.fsm.state[CORE_NEXT];     // inter-block (0 for SHA-3)
        // Tail = residual one-time output/squeeze cost (exact by construction).
        const long long tail   = static_cast<long long>(r.lat1blk) - lead - init
                                 - static_cast<long long>(r.one.fsm.state[CORE_ABSORB])
                                 - static_cast<long long>(r.one.fsm.state[CORE_ROUNDS]);
        const long long fixed  = static_cast<long long>(r.lat1blk) - roundToInt(r.per_block);

        const std::string absorb_s = sha3 ? std::to_string(absorb) : std::string("-");
        const std::string gap_s    = sha3 ? std::string("-")       : std::to_string(gap);

        std::cout << "| " << std::left << std::setw(12) << name << std::right
                  << " | " << std::setw(4) << lead
                  << " | " << std::setw(4) << init
                  << " | " << std::setw(6) << absorb_s
                  << " | " << std::setw(6) << rounds
                  << " | " << std::setw(4) << gap_s
                  << " | " << std::setw(4) << tail
                  << " | " << std::setw(5) << fixed
                  << " | " << std::setw(6) << roundToInt(r.per_block)
                  << " |\n";
    }
    std::cout << "|--------------|------|------|--------|--------|------|------|-------|--------|\n";

    //---------------------------------------------------------------------------------
    //  Notes
    //---------------------------------------------------------------------------------
    std::cout << "\nNotes:\n";
    std::cout << "  Latency[cycles] = Fixed + Nblk x PerBlk, exactly, where Nblk = number of\n";
    std::cout << "             internal blocks = ceil((msg + padding) / Block). The 1blk/64blk\n";
    std::cout << "             samples are 55 B and 4 KiB messages (= 1 and 65 internal blocks).\n";
    std::cout << "  Fixed    = one-time overhead (= Lat1blk - PerBlk) = Lead + Init + Tail - Gap\n";
    std::cout << "             (see cycle-phase breakdown). This is a fitted intercept, NOT the\n";
    std::cout << "             init count: the inter-block Gap is folded into PerBlk, so for SHA-2\n";
    std::cout << "             it is subtracted back out here. Measured end-to-end (external start\n";
    std::cout << "             asserted .. busy deasserts for good).\n";
    std::cout << "  PerBlk   = steady-state cost per compression/permutation block, per lane\n";
    std::cout << "             (= Rounds + Absorb + Gap), from (Lat64 - Lat32)/32 so Fixed cancels.\n";
    std::cout << "  +duet    = SHA-224/256 only: both 32-bit lanes carry data. Same cycles as the\n";
    std::cout << "             base row (one FSM, lanes in lockstep); 2x throughput (stride 128 B\n";
    std::cout << "             per block-pair vs 64 B single-lane).\n";
    std::cout << "  Throughput = 8 * stride_bytes * f_clk / PerBlk  [Mbps];  MB/s = Mbps / 8.\n";
    std::cout << "  * SHAKE128/256 are XOF; transaction end is the output_ready-low squeeze-STOP.\n";
    std::cout << "  Per-mode FSM-state breakdown and busy-cycle window: run with VERBOSE=1"
                 " (--verbose 1).\n";

    return 0;
}

REGISTER_TEST("performance", run_performance);

}  // namespace
}  // namespace sharmony
