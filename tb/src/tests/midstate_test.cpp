///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Midstate caching (state_load / state_save / state_cache) functional tests:
// save/load round-trips (SHA-2, SHA-3/SHAKE, duet), resume+finalize digests,
// the internal cache-slot suite, and the midstate/cache corner batch.
//
// The core round-trip check validates the load path without needing an
// external reference:
//
//   MS after [B1][B2]              (compute 2 blocks, export state)
//     ==
//   state_load(MS-after-B1) + B2  (resume from saved state, export state)
//
///////////////////////////////////////////////////////////////////////////////////////

#include "../SharmonyDriver.hpp"
#include "../TestRegistry.hpp"
#include "Vsharmony_verilator_wrapper.h"             // SCRATCH: full model (case2b)
#include "Vsharmony_verilator_wrapper___024root.h"  // SCRATCH: H_q whitebox probe (case2b)

#include <cstdint>
#include <iostream>
#include <vector>

using namespace sharmony;

namespace {

// Export the full midstate: optionally load `loadMS` first, then stream the
// block-aligned `data`, then collect `nbeats` exported state words.
std::vector<uint64_t> saveState(SharmonyDriver& drv, Mode m,
                                const std::vector<uint8_t>& data,
                                size_t nbeats,
                                const std::vector<uint64_t>* loadMS) {
    drv.reset();
    drv.setMode(m);
    drv.setOutReady(true);
    drv.setStateLoad(loadMS != nullptr);
    drv.setStateSave(true);

    if (!drv.tryPulseStart(500)) {
        std::cerr << "[midstate] pulseStart timed out\n";
        return {};
    }

    // state_load prefix: stream the saved state words raw (not final).
    if (loadMS) {
        for (uint64_t w : *loadMS)
            if (!drv.trySendBeat(w, 8, 0b00, 4000)) {
                std::cerr << "[midstate] state-word beat refused\n";
                return {};
            }
    }

    // Block-aligned data; sendMessageNative marks the last beat final, which
    // (with state_save) triggers the no-pad export.
    drv.sendMessageNative(data);

    auto res = drv.tryCollectBeats(nbeats, 8000);
    drv.setStateLoad(false);
    drv.setStateSave(false);
    if (!res.first) std::cerr << "[midstate] export collect timed out\n";
    return res.second;
}

bool eq(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b) {
    return a.size() == b.size() && a == b && !a.empty();
}

void dump(const char* tag, const std::vector<uint64_t>& v) {
    std::cout << "  " << tag << " (" << v.size() << "):";
    for (uint64_t w : v) std::cout << " " << std::hex << w;
    std::cout << std::dec << "\n";
}

int roundTrip(SharmonyDriver& drv, Mode m, size_t blockBytes, size_t nbeats,
              const char* name) {
    // Two distinct block-aligned blocks.
    std::vector<uint8_t> B1(blockBytes), B2(blockBytes);
    for (size_t i = 0; i < blockBytes; ++i) { B1[i] = uint8_t(i + 1); B2[i] = uint8_t(0xA0 ^ i); }
    std::vector<uint8_t> B1B2 = B1; B1B2.insert(B1B2.end(), B2.begin(), B2.end());

    auto ms1        = saveState(drv, m, B1,  nbeats, nullptr);   // after B1
    auto ms2_direct = saveState(drv, m, B1B2, nbeats, nullptr);  // after B1||B2
    auto ms2_resume = saveState(drv, m, B2,  nbeats, &ms1);      // load ms1, then B2

    bool ok = eq(ms2_resume, ms2_direct) && !eq(ms1, ms2_direct);
    if (!ok) {
        std::cerr << "[FAIL] [midstate] " << name << "\n";
        dump("ms1       ", ms1);
        dump("ms2_direct", ms2_direct);
        dump("ms2_resume", ms2_resume);
    } else {
        std::cout << "[PASS] [midstate] " << name << "\n";
    }
    return ok ? 0 : 1;
}

// Normal finalize: hash `msg` -> digest beats (as collected, SHA-2 reverse order).
std::vector<uint64_t> hashDigest(SharmonyDriver& drv, Mode m,
                                 const std::vector<uint8_t>& msg) {
    drv.reset();
    drv.setMode(m);
    drv.setOutReady(true);
    drv.setStateLoad(false);
    drv.setStateSave(false);
    if (!drv.tryPulseStart(500)) return {};
    drv.sendMessageNative(msg);
    return drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000).second;
}

// Resume + finalize: load MS (prefix state), stream the tail, finalize -> digest.
std::vector<uint64_t> resumeDigest(SharmonyDriver& drv, Mode m,
                                   const std::vector<uint64_t>& ms,
                                   const std::vector<uint8_t>& tail) {
    drv.reset();
    drv.setMode(m);
    drv.setOutReady(true);
    drv.setStateLoad(true);
    drv.setStateSave(false);
    if (!drv.tryPulseStart(500)) return {};
    for (uint64_t w : ms)
        if (!drv.trySendBeat(w, 8, 0b00, 4000)) return {};
    drv.sendMessageNative(tail);
    auto out = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000).second;
    drv.setStateLoad(false);
    return out;
}

// hash(prefix||tail) == state_load(save(prefix)) + tail -> finalize.
// msBeats = midstate size (8 for SHA-2 H_q, 25 for SHA-3 R_q).
int resumeFinalize(SharmonyDriver& drv, Mode m, size_t blockBytes, size_t msBeats,
                   const char* name) {
    std::vector<uint8_t> prefix(blockBytes), tail(37);
    for (size_t i = 0; i < blockBytes; ++i) prefix[i] = uint8_t(i * 3 + 7);
    for (size_t i = 0; i < tail.size(); ++i) tail[i]   = uint8_t(0x5A ^ i);
    std::vector<uint8_t> full = prefix; full.insert(full.end(), tail.begin(), tail.end());

    auto ms     = saveState(drv, m, prefix, msBeats, nullptr);  // MS after 1-block prefix
    auto d_norm = hashDigest(drv, m, full);
    auto d_res  = resumeDigest(drv, m, ms, tail);

    bool ok = !d_norm.empty() && d_norm == d_res;
    if (ok) {
        std::cout << "[PASS] [midstate] " << name << "\n";
    } else {
        std::cerr << "[FAIL] [midstate] " << name << "\n";
        dump("d_norm", d_norm);
        dump("d_res ", d_res);
    }
    return ok ? 0 : 1;
}

// Internal cache (state_cache): cache-save a prefix (MS stays in H_q, NO reset),
// then cache-resume the tail -> digest. Compare to one-shot hash(prefix||tail).
int cacheResumeFinalize(SharmonyDriver& drv, Mode m, size_t blockBytes,
                        const char* name) {
    std::vector<uint8_t> prefix(blockBytes), tail(37);
    for (size_t i = 0; i < blockBytes; ++i) prefix[i] = uint8_t(i * 3 + 7);
    for (size_t i = 0; i < tail.size(); ++i) tail[i]   = uint8_t(0x5A ^ i);
    std::vector<uint8_t> full = prefix; full.insert(full.end(), tail.begin(), tail.end());

    auto d_norm = hashDigest(drv, m, full);   // one-shot reference (resets internally)

    // cache-save the prefix: block-aligned, no pad, no output; MS left in H_q.
    drv.reset();
    drv.setMode(m);
    drv.setOutReady(true);
    drv.setStateCache(true);
    drv.setStateSave(true);
    drv.setStateLoad(false);
    if (!drv.tryPulseStart(500)) return 1;
    drv.sendMessageNative(prefix);
    drv.setStateSave(false);
    // wait save done (no reset!) + output-silence check: a cache-save that
    // raises output_valid is leaking the on-chip mid-state.
    uint64_t save_leak = 0;
    for (int i = 0; i < 500 && drv.busy(); ++i) {
        drv.tick();
        if (drv.outputValid()) save_leak++;
    }
    if (save_leak != 0) {
        std::cerr << "[FAIL] [midstate] " << name << ": cache-save leaked "
                  << save_leak << " output beat(s)\n";
        return 1;
    }

    // cache-resume the tail: H_q already holds the MS (no streaming, no reset).
    drv.setStateCache(true);
    drv.setStateLoad(true);
    drv.setStateSave(false);
    if (!drv.tryPulseStart(500)) return 1;
    drv.sendMessageNative(tail);
    auto d_cache = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000).second;
    drv.setStateLoad(false);
    drv.setStateCache(false);

    bool ok = !d_norm.empty() && d_norm == d_cache;
    if (ok) {
        std::cout << "[PASS] [midstate] " << name << "\n";
    } else {
        std::cerr << "[FAIL] [midstate] " << name << "\n";
        dump("d_norm ", d_norm);
        dump("d_cache", d_cache);
    }
    return ok ? 0 : 1;
}

// Cache MULTI-resume: cache-save once, then resume TWICE from the same cached MS
// (different tails). Verifies H_q returns to the MS after each resume (MS-landing).
int cacheMultiResume(SharmonyDriver& drv, Mode m, size_t blockBytes, const char* name) {
    std::vector<uint8_t> prefix(blockBytes), tailA(37), tailB(50);
    for (size_t i = 0; i < blockBytes; ++i) prefix[i] = uint8_t(i * 3 + 7);
    for (size_t i = 0; i < tailA.size(); ++i) tailA[i] = uint8_t(0x5A ^ i);
    for (size_t i = 0; i < tailB.size(); ++i) tailB[i] = uint8_t(0xA5 + i);
    std::vector<uint8_t> fullA = prefix; fullA.insert(fullA.end(), tailA.begin(), tailA.end());
    std::vector<uint8_t> fullB = prefix; fullB.insert(fullB.end(), tailB.begin(), tailB.end());
    auto dnA = hashDigest(drv, m, fullA);
    auto dnB = hashDigest(drv, m, fullB);

    drv.reset(); drv.setMode(m); drv.setOutReady(true);
    drv.setStateCache(true); drv.setStateSave(true); drv.setStateLoad(false);
    if (!drv.tryPulseStart(500)) return 1;
    drv.sendMessageNative(prefix);
    drv.setStateSave(false);
    uint64_t save_leak = 0;
    for (int i = 0; i < 500 && drv.busy(); ++i) {
        drv.tick();
        if (drv.outputValid()) save_leak++;
    }
    if (save_leak != 0) {
        std::cerr << "[FAIL] [midstate] " << name << ": cache-save leaked "
                  << save_leak << " output beat(s)\n";
        return 1;
    }

    auto resume = [&](const std::vector<uint8_t>& tail) {
        drv.setStateCache(true); drv.setStateLoad(true); drv.setStateSave(false);
        if (!drv.tryPulseStart(500)) return std::vector<uint64_t>{};
        drv.sendMessageNative(tail);
        auto d = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000).second;
        for (int i = 0; i < 500 && drv.busy(); ++i) drv.tick();
        return d;
    };
    auto dcA = resume(tailA);
    auto dcB = resume(tailB);   // SECOND resume from the same cached MS
    drv.setStateLoad(false); drv.setStateCache(false);

    bool ok = !dnA.empty() && dnA == dcA && !dnB.empty() && dnB == dcB;
    if (ok) {
        std::cout << "[PASS] [midstate] " << name << "\n";
    } else {
        std::cerr << "[FAIL] [midstate] " << name << " (A " << (dnA==dcA?"ok":"BAD")
                  << ", B " << (dnB==dcB?"ok":"BAD") << ")\n";
        dump("dnA", dnA); dump("dcA", dcA); dump("dnB", dnB); dump("dcB", dcB);
    }
    return ok ? 0 : 1;
}

//-------------------------------------------------------------------------------------
//  Duet variants (SHA-224/256 run as 2-lane parallel; mirror both lanes)
//-------------------------------------------------------------------------------------
std::vector<uint64_t> saveStateDuet(SharmonyDriver& drv, Mode m,
                                    const std::vector<uint8_t>& data,
                                    const std::vector<uint64_t>* loadMS) {
    drv.reset(); drv.setMode(m); drv.setOutReady(true);
    drv.setStateLoad(loadMS != nullptr); drv.setStateSave(true);
    if (!drv.tryPulseStart(500)) return {};
    if (loadMS) for (uint64_t w : *loadMS) if (!drv.trySendBeat(w, 8, 0b00, 4000)) return {};
    drv.sendMessageDuetMirror(data);
    auto res = drv.tryCollectBeats(8, 8000);
    drv.setStateLoad(false); drv.setStateSave(false);
    return res.second;
}

std::vector<uint64_t> hashDigestDuet(SharmonyDriver& drv, Mode m,
                                     const std::vector<uint8_t>& msg) {
    drv.reset(); drv.setMode(m); drv.setOutReady(true);
    drv.setStateLoad(false); drv.setStateSave(false);
    if (!drv.tryPulseStart(500)) return {};
    drv.sendMessageDuetMirror(msg);
    return drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000).second;
}

std::vector<uint64_t> resumeDigestDuet(SharmonyDriver& drv, Mode m,
                                       const std::vector<uint64_t>& ms,
                                       const std::vector<uint8_t>& tail) {
    drv.reset(); drv.setMode(m); drv.setOutReady(true);
    drv.setStateLoad(true); drv.setStateSave(false);
    if (!drv.tryPulseStart(500)) return {};
    for (uint64_t w : ms) if (!drv.trySendBeat(w, 8, 0b00, 4000)) return {};
    drv.sendMessageDuetMirror(tail);
    auto out = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000).second;
    drv.setStateLoad(false);
    return out;
}

int roundTripDuet(SharmonyDriver& drv, Mode m, const char* name) {
    std::vector<uint8_t> B1(64), B2(64);   // 1 duet block per lane = 64 bytes
    for (int i = 0; i < 64; ++i) { B1[i] = uint8_t(i + 1); B2[i] = uint8_t(0xA0 ^ i); }
    std::vector<uint8_t> B1B2 = B1; B1B2.insert(B1B2.end(), B2.begin(), B2.end());
    auto ms1 = saveStateDuet(drv, m, B1, nullptr);
    auto ms2_direct = saveStateDuet(drv, m, B1B2, nullptr);
    auto ms2_resume = saveStateDuet(drv, m, B2, &ms1);
    bool ok = eq(ms2_resume, ms2_direct) && !eq(ms1, ms2_direct);
    if (ok) std::cout << "[PASS] [midstate] " << name << "\n";
    else { std::cerr << "[FAIL] [midstate] " << name << "\n";
           dump("ms1", ms1); dump("ms2_direct", ms2_direct); dump("ms2_resume", ms2_resume); }
    return ok ? 0 : 1;
}

int resumeFinalizeDuet(SharmonyDriver& drv, Mode m, const char* name) {
    std::vector<uint8_t> prefix(64), tail(37);
    for (int i = 0; i < 64; ++i)        prefix[i] = uint8_t(i * 3 + 7);
    for (size_t i = 0; i < tail.size(); ++i) tail[i] = uint8_t(0x5A ^ i);
    std::vector<uint8_t> full = prefix; full.insert(full.end(), tail.begin(), tail.end());
    auto ms     = saveStateDuet(drv, m, prefix, nullptr);
    auto d_norm = hashDigestDuet(drv, m, full);
    auto d_res  = resumeDigestDuet(drv, m, ms, tail);
    bool ok = !d_norm.empty() && d_norm == d_res;
    if (ok) std::cout << "[PASS] [midstate] " << name << "\n";
    else { std::cerr << "[FAIL] [midstate] " << name << "\n"; dump("d_norm", d_norm); dump("d_res ", d_res); }
    return ok ? 0 : 1;
}

// Spec-figure scenario (make run-midstate_cache VCD=1): SHA-512 CACHE-save of a
// one-block prefix (state_cache & state_save: chaining value kept on-chip,
// NO export beats), then TWO cache-resumes from the same cached value
// (state_cache & state_load: no re-streamed state, tail -> digest). The
// second resume gives the figure a reuse transaction. The three cache
// transactions run FIRST so the figure windows sit early in the VCD; the
// one-shot reference hashes that verify both digests run after them.
int run_midstate_cache(SharmonyDriver& drv, const TestOptions& opts) {
    (void)opts;
    const Mode m = Mode::SHA2_512;
    std::vector<uint8_t> prefix(128), tailA(8), tailB(8);
    for (size_t i = 0; i < prefix.size(); ++i) prefix[i] = uint8_t(i + 1);
    for (size_t i = 0; i < tailA.size(); ++i)  tailA[i]  = uint8_t(0x5A ^ i);
    for (size_t i = 0; i < tailB.size(); ++i)  tailB[i]  = uint8_t(0xA5 + i);

    // cache-save the prefix: block-aligned, no pad, no output beats.
    drv.reset();
    drv.setMode(m);
    drv.setOutReady(true);
    drv.setStateCache(true);
    drv.setStateSave(true);
    drv.setStateLoad(false);
    if (!drv.tryPulseStart(500)) return 1;
    drv.sendMessageNative(prefix);
    drv.endMsg();            // deassert input_valid once the prefix is delivered
    drv.setStateSave(false);
    // Cache-save must be silent on the output bus: any output_valid beat here
    // is a mid-state leak (the chaining value must stay on-chip).
    uint64_t leak_beats = 0;
    for (int i = 0; i < 500 && drv.busy(); ++i) {
        drv.tick();
        if (drv.outputValid()) leak_beats++;
    }
    if (leak_beats != 0) {
        std::cerr << "[FAIL] [midstate_cache] cache-save leaked " << leak_beats
                  << " output beat(s) (output_valid during save)\n";
        return 1;
    }

    auto resume = [&](const std::vector<uint8_t>& tail) {
        drv.setStateCache(true);
        drv.setStateLoad(true);
        drv.setStateSave(false);
        if (!drv.tryPulseStart(500)) return std::vector<uint64_t>{};
        drv.sendMessageNative(tail);
        drv.endMsg();        // deassert input_valid once the tail is delivered
        auto d = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000).second;
        for (int i = 0; i < 500 && drv.busy(); ++i) drv.tick();
        return d;
    };
    auto dcA = resume(tailA);
    auto dcB = resume(tailB);
    drv.setStateLoad(false);
    drv.setStateCache(false);

    // One-shot references (after the figure transactions; reset internally).
    std::vector<uint8_t> fullA = prefix; fullA.insert(fullA.end(), tailA.begin(), tailA.end());
    std::vector<uint8_t> fullB = prefix; fullB.insert(fullB.end(), tailB.begin(), tailB.end());
    auto dnA = hashDigest(drv, m, fullA);
    auto dnB = hashDigest(drv, m, fullB);

    const bool ok = !dnA.empty() && dnA == dcA && !dnB.empty() && dnB == dcB;
    if (ok) {
        std::cout << "[PASS] [midstate_cache] figure (cache-save + 2x cache-resume) verified\n";
    } else {
        std::cerr << "[FAIL] [midstate_cache] (A " << (dnA == dcA ? "ok" : "BAD")
                  << ", B " << (dnB == dcB ? "ok" : "BAD") << ")\n";
        dump("dnA", dnA); dump("dcA", dcA); dump("dnB", dnB); dump("dcB", dcB);
    }
    return ok ? 0 : 1;
}

// Cache robustness batches, defined below; folded into the aggregate run.
int cacheMultiBlockSweep(SharmonyDriver& drv);
int cacheDuetSweep(SharmonyDriver& drv);
int cacheDuetAsymmetric(SharmonyDriver& drv);
int midstateCornerBatch(SharmonyDriver& drv);

int run_midstate(SharmonyDriver& drv, const TestOptions& opts) {
    // Spec-figure mode: one clean SHA-512 save->resume round-trip in a single
    // VCD (reuses saveState/resumeDigest; no extra test logic). Shows the
    // mid-state EXPORT (state_save) then RE-IMPORT (state_load) + tail -> digest.
    if (opts.figure_trace) {
        const Mode m = Mode::SHA2_512;          // single-lane, 8-beat H_q state
        std::vector<uint8_t> B1(128), tail(8);  // 1 block (16 beats) + 1 tail beat
        for (size_t i = 0; i < B1.size();  ++i) B1[i]  = uint8_t(i + 1);
        for (size_t i = 0; i < tail.size(); ++i) tail[i] = uint8_t(0x5A ^ i);
        auto ms = saveState(drv, m, B1, 8, nullptr);   // SAVE: export MS0..MS7
        if (ms.size() != 8) { std::cerr << "[midstate] figure save failed\n"; return 1; }
        auto d = resumeDigest(drv, m, ms, tail);        // RESUME: load MS + tail -> digest
        if (d.empty()) { std::cerr << "[midstate] figure resume failed\n"; return 1; }
        std::cout << "[midstate] figure (save->resume round-trip) done\n";
        return 0;
    }

    int fails = 0;
    // midstate = 8 beats (full 8-word H) for every SHA-2 mode.
    // 64-bit modes: 128-byte block; 32-bit modes: 64-byte block.
    fails += roundTrip(drv, Mode::SHA2_512,     128, 8, "sha512_roundtrip");
    fails += roundTrip(drv, Mode::SHA2_384,     128, 8, "sha384_roundtrip");
    fails += roundTrip(drv, Mode::SHA2_512_256, 128, 8, "sha512_256_roundtrip");
    fails += roundTrip(drv, Mode::SHA2_512_224, 128, 8, "sha512_224_roundtrip");
    // SHA-256/224 are 2-lane duet; mirror both lanes (block = 64 bytes/lane).
    fails += roundTripDuet(drv, Mode::SHA2_256, "sha256_roundtrip");
    fails += roundTripDuet(drv, Mode::SHA2_224, "sha224_roundtrip");

    // Resume + Finalize -> digest (1-block prefix), SHA-2 (8-beat H_q midstate).
    fails += resumeFinalize(drv, Mode::SHA2_512,     128, 8, "sha512_resume_finalize");
    fails += resumeFinalize(drv, Mode::SHA2_384,     128, 8, "sha384_resume_finalize");
    fails += resumeFinalize(drv, Mode::SHA2_512_256, 128, 8, "sha512_256_resume_finalize");
    fails += resumeFinalize(drv, Mode::SHA2_512_224, 128, 8, "sha512_224_resume_finalize");
    fails += resumeFinalizeDuet(drv, Mode::SHA2_256, "sha256_resume_finalize");
    fails += resumeFinalizeDuet(drv, Mode::SHA2_224, "sha224_resume_finalize");

    // Internal 1-slot cache (state_cache): SHA-2 single-lane (SHA-512 family).
    fails += cacheResumeFinalize(drv, Mode::SHA2_512, 128, "sha512_cache_resume");
    fails += cacheMultiResume(drv, Mode::SHA2_512, 128, "sha512_cache_multiresume");

    //---------------------------------------------------------------------------------
    //  SHA-3 / SHAKE: 25-lane R_q midstate; block = rate (bytes).
    //---------------------------------------------------------------------------------
    // rates: SHA3-224=144 256=136 384=104 512=72  SHAKE128=168 SHAKE256=136
    fails += roundTrip(drv, Mode::SHA3_256,  136, 25, "sha3_256_roundtrip");
    fails += roundTrip(drv, Mode::SHA3_512,   72, 25, "sha3_512_roundtrip");
    fails += roundTrip(drv, Mode::SHA3_224,  144, 25, "sha3_224_roundtrip");
    fails += roundTrip(drv, Mode::SHA3_384,  104, 25, "sha3_384_roundtrip");
    fails += roundTrip(drv, Mode::SHAKE128,  168, 25, "shake128_roundtrip");
    fails += roundTrip(drv, Mode::SHAKE256,  136, 25, "shake256_roundtrip");
    // SHA-3 Resume+Finalize -> digest (hash modes; SHAKE squeeze is variable-len).
    fails += resumeFinalize(drv, Mode::SHA3_256, 136, 25, "sha3_256_resume_finalize");
    fails += resumeFinalize(drv, Mode::SHA3_512,  72, 25, "sha3_512_resume_finalize");
    fails += resumeFinalize(drv, Mode::SHA3_224, 144, 25, "sha3_224_resume_finalize");
    fails += resumeFinalize(drv, Mode::SHA3_384, 104, 25, "sha3_384_resume_finalize");

    // Cache robustness batches: multi-block resume tails (SHA-2-64 family),
    // duet cache (the WOTS/SPHINCS+ mode), and the corner-case expectation
    // batch (zeroize/cross-family/slot/wedge-guard checks).
    fails += cacheMultiBlockSweep(drv);
    fails += cacheDuetSweep(drv);
    fails += cacheDuetAsymmetric(drv);
    fails += midstateCornerBatch(drv);

    std::cout << "[midstate] DONE fails=" << fails << "\n";
    return fails == 0 ? 0 : 1;
}

//-------------------------------------------------------------------------------------
//  Shared internal-cache helpers (NO reset inside -- the cache slot lives in
//  H_q and must survive between save and resume; the caller owns reset).
//-------------------------------------------------------------------------------------
void cacheWaitIdle(SharmonyDriver& drv) {
    for (int i = 0; i < 2000 && drv.busy(); ++i) drv.tick();
}

// cache-save `data` (block-aligned); resume=true chains from the on-chip slot.
bool cacheSaveNR(SharmonyDriver& drv, Mode m, const std::vector<uint8_t>& data,
                 bool resume = false, bool duet = false) {
    drv.setMode(m); drv.setOutReady(true);
    drv.setStateCache(true); drv.setStateSave(true); drv.setStateLoad(resume);
    if (!drv.tryPulseStart(500)) return false;
    if (duet) drv.sendMessageDuetMirror(data); else drv.sendMessageNative(data);
    drv.endMsg();
    drv.setStateSave(false); drv.setStateLoad(false);
    cacheWaitIdle(drv);
    return true;
}

// cache-resume + finalize `tail` -> digest beats.
std::vector<uint64_t> cacheFinalizeNR(SharmonyDriver& drv, Mode m,
                                      const std::vector<uint8_t>& tail,
                                      bool duet = false) {
    drv.setMode(m); drv.setOutReady(true);
    drv.setStateCache(true); drv.setStateLoad(true); drv.setStateSave(false);
    std::vector<uint64_t> d;
    if (drv.tryPulseStart(500)) {
        if (duet) drv.sendMessageDuetMirror(tail); else drv.sendMessageNative(tail);
        drv.endMsg();
        d = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000).second;
    }
    drv.setStateLoad(false); drv.setStateCache(false);
    cacheWaitIdle(drv);
    return d;
}

//-------------------------------------------------------------------------------------
//  Cache resume+finalize with MULTI-BLOCK tails, SHA-2-64 family.  Tails sweep
//  the single-block edge (111/112 for SHA-512) into multi-block territory --
//  guards the blk_final_q gating of the cache_resume digest arrangement.
//-------------------------------------------------------------------------------------
int cacheMultiBlockSweep(SharmonyDriver& drv) {
    int bad = 0;
    const size_t tails[] = {1, 55, 111, 112, 128, 191, 200, 256, 300};
    struct { Mode m; const char* nm; } modes64[] = {
        {Mode::SHA2_512, "sha512"}, {Mode::SHA2_384, "sha384"},
        {Mode::SHA2_512_256, "sha512_256"}, {Mode::SHA2_512_224, "sha512_224"},
    };
    for (auto& md : modes64) {
        for (size_t ts : tails) {
            std::vector<uint8_t> pf(128), tt(ts);
            for (size_t i = 0; i < pf.size(); ++i) pf[i] = uint8_t(i * 7 + 3);
            for (size_t i = 0; i < ts;        ++i) tt[i] = uint8_t(0x33 ^ (i * 5));
            std::vector<uint8_t> whole = pf; whole.insert(whole.end(), tt.begin(), tt.end());
            auto dref = hashDigest(drv, md.m, whole);
            drv.reset();
            cacheSaveNR(drv, md.m, pf);
            auto dres = cacheFinalizeNR(drv, md.m, tt);
            if (!eq(dres, dref)) {
                ++bad;
                std::cerr << "[FAIL] [midstate] cache_multiblock " << md.nm
                          << " tail=" << ts << "\n";
            }
        }
    }
    if (bad == 0) std::cout << "[PASS] [midstate] cache_multiblock_sweep (36 combos)\n";
    return bad == 0 ? 0 : 1;
}

//-------------------------------------------------------------------------------------
//  DUET (SHA-256/224) internal-cache resume+finalize -- the WOTS/SPHINCS+ mode.
//  Tails sweep the SHA-256 single-block edge (55 B) into multi-block territory.
//-------------------------------------------------------------------------------------
int cacheDuetSweep(SharmonyDriver& drv) {
    int bad = 0;
    struct { Mode m; const char* nm; } modes[] = {
        {Mode::SHA2_256, "sha256"}, {Mode::SHA2_224, "sha224"},
    };
    const size_t tails[] = {1, 38, 54, 55, 56, 64, 100, 120};
    for (auto& md : modes) {
        for (size_t ts : tails) {
            std::vector<uint8_t> pf(64), tt(ts);
            for (size_t i = 0; i < pf.size(); ++i) pf[i] = uint8_t(i * 7 + 3);
            for (size_t i = 0; i < ts;        ++i) tt[i] = uint8_t(0x33 ^ (i * 5));
            std::vector<uint8_t> whole = pf; whole.insert(whole.end(), tt.begin(), tt.end());
            auto dref = hashDigestDuet(drv, md.m, whole);
            drv.reset();
            cacheSaveNR(drv, md.m, pf, false, /*duet=*/true);
            auto dres = cacheFinalizeNR(drv, md.m, tt, /*duet=*/true);
            if (!eq(dres, dref)) {
                ++bad;
                std::cerr << "[FAIL] [midstate] cache_duet " << md.nm
                          << " tail=" << ts << "\n";
            }
        }
    }
    if (bad == 0) std::cout << "[PASS] [midstate] cache_duet_sweep (16 combos)\n";
    return bad == 0 ? 0 : 1;
}

//-------------------------------------------------------------------------------------
// ASYMMETRIC-content duet internal cache: each lane carries a DIFFERENT
// message through cache-save + cache-resume (the mirror sweep above proves
// the mechanism; this proves the lanes stay independent through the slot).
// Prefixes are 64 B/lane (block-aligned); tails sweep the single-block edge
// and multi-block resume, plus two different-length lane pairs (one lane
// finalizes early and idles). Reference = one-shot asymmetric duet hash.
//-------------------------------------------------------------------------------------
int cacheDuetAsymmetric(SharmonyDriver& drv) {
    const Mode m = Mode::SHA2_256;
    const size_t nb = static_cast<size_t>(digestBeatsFor(m));
    int bad = 0;
    struct { size_t hi, lo; } tails[] = {
        {1,1}, {38,38}, {54,54}, {55,55}, {56,56}, {100,100}, {120,120},
        {54,20}, {20,54},                       // different lengths per lane
    };
    std::vector<uint8_t> pfhi(64), pflo(64);
    for (size_t i = 0; i < 64; ++i) { pfhi[i] = uint8_t(i * 7 + 3); pflo[i] = uint8_t(0xC3 ^ (i * 5)); }

    for (auto& t : tails) {
        std::vector<uint8_t> thi(t.hi), tlo(t.lo);
        for (size_t i = 0; i < t.hi; ++i) thi[i] = uint8_t(0x11 + i);
        for (size_t i = 0; i < t.lo; ++i) tlo[i] = uint8_t(0xEE - i);
        std::vector<uint8_t> whi = pfhi; whi.insert(whi.end(), thi.begin(), thi.end());
        std::vector<uint8_t> wlo = pflo; wlo.insert(wlo.end(), tlo.begin(), tlo.end());

        // one-shot asymmetric duet reference
        drv.reset(); drv.setMode(m); drv.setOutReady(true);
        drv.setStateLoad(false); drv.setStateSave(false); drv.setStateCache(false);
        std::vector<uint64_t> dref;
        if (drv.tryPulseStart(500)) {
            drv.sendMessagesDuet(whi, wlo);
            dref = drv.tryCollectBeats(nb, 8000).second;
        }
        cacheWaitIdle(drv);

        // asymmetric cache-save (silent), then asymmetric cache-resume
        drv.reset(); drv.setMode(m); drv.setOutReady(true);
        drv.setStateCache(true); drv.setStateSave(true); drv.setStateLoad(false);
        std::vector<uint64_t> dres;
        if (drv.tryPulseStart(500)) {
            drv.sendMessagesDuet(pfhi, pflo); drv.endMsg();
            drv.setStateSave(false);
            cacheWaitIdle(drv);
            drv.setStateCache(true); drv.setStateLoad(true);
            if (drv.tryPulseStart(500)) {
                drv.sendMessagesDuet(thi, tlo); drv.endMsg();
                dres = drv.tryCollectBeats(nb, 8000).second;
            }
        }
        drv.setStateLoad(false); drv.setStateCache(false);
        cacheWaitIdle(drv);

        if (!eq(dres, dref)) {
            ++bad;
            std::cerr << "[FAIL] [midstate] cache_duet_asym hi=" << t.hi
                      << " lo=" << t.lo << "\n";
            dump("dref", dref); dump("dres", dres);
        }
    }
    if (bad == 0) std::cout << "[PASS] [midstate] cache_duet_asymmetric (9 combos)\n";
    return bad == 0 ? 0 : 1;
}

//-------------------------------------------------------------------------------------
// case2b: 111-combo (load+save+cache) policy regression + legal-path checks.
//
// Under RESUME-WINS (the shipped policy), asserting all three state pins is
// a cache-resume + finalize: the save request is ignored and the slot stays
// valid (it lands at the last full-block boundary). The test verifies (a) the
// 111 digest equals hash(prefix||message), (b) a follow-up resume matches the
// clean 2-block slot, and (c) the legal 110 block-spanning-tail resume; the
// 2-block TRUE-chaining probe is report-only. Historical note: pre-fix, 111 saved
// H_q in the finalize arrangement -> silently corrupted slot (whitebox-
// diagnosed here via the H_q probe, which the WHOLE leg still exercises).
//-------------------------------------------------------------------------------------
int run_case2b(SharmonyDriver& drv, const TestOptions&) {
    const Mode m = Mode::SHA2_512;
    auto* root = drv.model()->rootp;
    auto readHQ = [&]() {
        std::vector<uint64_t> h(8);
        for (int i = 0; i < 8; ++i)
            h[i] = root->sharmony_verilator_wrapper__DOT__dut__DOT__core_inst__DOT__H_q[i];
        return h;
    };
    auto waitIdle = [&]() { for (int i = 0; i < 800 && drv.busy(); ++i) drv.tick(); };

    // cache-save `data` (block-aligned); resume=true resumes on-chip H_q first.
    // Returns false when the start is refused (busy never rises) -- the 111
    // resume+save-again combo is blocked outright once a start guard exists.
    auto cacheSave = [&](const std::vector<uint8_t>& data, bool resume) {
        drv.setStateCache(true); drv.setStateSave(true); drv.setStateLoad(resume);
        bool accepted = drv.tryPulseStart(500) && drv.busy();
        if (accepted) drv.sendMessageNative(data);
        drv.setStateSave(false); drv.setStateLoad(false);
        waitIdle();
        return accepted;
    };
    auto cacheFinalize = [&](const std::vector<uint8_t>& tail) {
        drv.setStateCache(true); drv.setStateLoad(true); drv.setStateSave(false);
        if (!drv.tryPulseStart(500)) return std::vector<uint64_t>{};
        drv.sendMessageNative(tail);
        auto d = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000).second;
        drv.setStateLoad(false); drv.setStateCache(false);
        return d;
    };

    std::vector<uint8_t> block1(128), block2(128), tail(37);
    for (size_t i = 0; i < 128; ++i) { block1[i] = uint8_t(i * 3 + 7); block2[i] = uint8_t(0xA0 ^ i); }
    for (size_t i = 0; i < tail.size(); ++i) tail[i] = uint8_t(0x5A ^ i);
    std::vector<uint8_t> two = block1;  two.insert(two.end(), block2.begin(), block2.end());
    std::vector<uint8_t> full = two;    full.insert(full.end(), tail.begin(), tail.end());

    // WHOLE: single silent cache-save of the 2-block prefix.
    drv.reset(); drv.setMode(m); drv.setOutReady(true);
    cacheSave(two, /*resume=*/false);
    auto hqWhole = readHQ();
    drv.setStateCache(false);

    // 111 under RESUME-WINS: cache-save block1, then assert load+save+cache
    // with block2 as the message. The save must be IGNORED and the operation
    // must behave as cache-resume + FINALIZE:
    //   digest == hash(block1||block2); the slot grows to the 2-block state.
    drv.reset(); drv.setMode(m); drv.setOutReady(true);
    cacheSave(block1, /*resume=*/false);
    drv.setStateCache(true); drv.setStateSave(true); drv.setStateLoad(true);   // 111
    std::vector<uint64_t> d111;
    bool started111 = drv.tryPulseStart(500) && drv.busy();
    if (started111) {
        drv.sendMessageNative(block2);
        d111 = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000).second;
    }
    drv.setStateSave(false); drv.setStateLoad(false);
    waitIdle();
    // follow-up-resume probe MUST run before any reset:
    auto d_after = cacheFinalize(tail);
    drv.setStateCache(false);
    waitIdle();

    // References.
    auto d_2blk    = hashDigest(drv, m, two);    // hash(block1||block2)
    auto d_oneshot = hashDigest(drv, m, full);   // hash(2blk||tail)

    drv.reset(); drv.setMode(m); drv.setOutReady(true);
    cacheSave(two, false);
    auto d_whole = cacheFinalize(tail);          // slot-preserved reference

    // Streamed reference: the TRUE 2-block chaining value, finalized with the
    // SAME (single-block) length seed as the cache paths.  Isolates chaining
    // correctness from the length-seed limitation.
    auto ms2_streamed  = saveState(drv, m, two, 8, nullptr);   // true MS after 2 blocks
    auto d_stream_res  = resumeDigest(drv, m, ms2_streamed, tail);

    bool whole_true_chain = eq(d_whole, d_stream_res);
    std::cout << "[case2b] digest(single 2-block cache) vs streamed-true-chaining resume: "
              << (whole_true_chain ? "MATCH -> single cache-save keeps TRUE chaining"
                                   : "DIFFER") << "\n";

    // Three possible 111 dispositions; the test reports which one the RTL
    // implements and only FAILS on inconsistency:
    //   (1) start guard      -> refused, nothing happens (slot preserved)
    //   (2) resume-wins      -> digest == hash(block1||block2); afterwards
    //       the slot sits at the last full-block boundary (== clean 2-block
    //       slot -- the output path never folds the padding block into H_q,
    //       the same property multiresume relies on)
    //   (3) neither (unguarded) -> silent (cache-save path taken), slot
    //       corrupted; reported as a warning, NOT a failure. The RTL pins
    //       disposition (2): the top-level mode latch masks state_save when
    //       state_load && state_cache are asserted with it (resume-wins).
    bool c111_ok = true;
    if (!started111) {
        std::cout << "[case2b] 111 combo: START REFUSED -> guard active\n";
    } else if (eq(d111, d_2blk)) {
        bool grown_ok = eq(d_after, d_whole);
        c111_ok = grown_ok;
        std::cout << "[case2b] 111 combo: RESUME-WINS -> digest == hash(block1||block2), save ignored\n";
        std::cout << "[case2b] 111 resume-wins: slot afterwards vs clean 2-block slot: "
                  << (grown_ok ? "MATCH -> slot at last full-block boundary (aligned prefix grew)"
                               : "DIFFER -> slot semantics inconsistent, revisit") << "\n";
    } else {
        std::cout << "[case2b] 111 combo: UNGUARDED -- op was "
                  << (d111.empty() ? "SILENT (cache-save path)" : "noisy")
                  << ", follow-up resume "
                  << (eq(d_after, d_whole) ? "matches clean slot (unexpected)"
                                           : "GIGO -> slot CORRUPTED as documented")
                  << "\n";
    }
    dump("hqWhole ", hqWhole);
    dump("d_2blk   ", d_2blk);
    dump("d111     ", d111);
    dump("d_oneshot", d_oneshot);
    dump("d_whole  ", d_whole);

    //---------------------------------------------------------------------------------
    //  LEGAL cache-resume+finalize with a BLOCK-SPANNING tail
    //---------------------------------------------------------------------------------
    // Supported path: 110 (state_cache+state_load, save=0).  Tail = 128 bytes
    // (exactly one block) => finalize needs a padding-overflow 2nd block, i.e.
    // an intermediate NON-final block boundary while cache_resume is high.
    // If this collides / asserts / mis-hashes, the supported single cache
    // resume+finalize path is limited to sub-block tails.
    std::vector<uint8_t> pfx(128), tl(128);
    for (size_t i = 0; i < pfx.size(); ++i) pfx[i] = uint8_t(i * 3 + 7);
    for (size_t i = 0; i < tl.size();  ++i) tl[i]  = uint8_t(0x5A ^ i);
    std::vector<uint8_t> pt = pfx; pt.insert(pt.end(), tl.begin(), tl.end());
    auto d_correct = hashDigest(drv, m, pt);

    drv.reset(); drv.setMode(m); drv.setOutReady(true);
    cacheSave(pfx, /*resume=*/false);                 // cache 1-block prefix
    drv.setStateCache(true); drv.setStateLoad(true); drv.setStateSave(false);  // 110 legal
    std::vector<uint64_t> d_big;
    if (drv.tryPulseStart(500)) {
        drv.sendMessageNative(tl);
        d_big = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000).second;
    }
    drv.setStateLoad(false); drv.setStateCache(false);

    bool bigtail_ok = eq(d_big, d_correct);
    std::cout << "[case2b] LEGAL 110 resume+finalize, block-spanning (128B) tail: "
              << (bigtail_ok ? "OK -> correct digest"
                             : "BROKEN -> wrong/empty digest (multi-block resume tail)") << "\n";

    //---------------------------------------------------------------------------------
    //  Robustness sweep (shared with run_midstate): multi-block tails
    //---------------------------------------------------------------------------------
    int sweep_fail = cacheMultiBlockSweep(drv);

    return (bigtail_ok && sweep_fail == 0 && c111_ok) ? 0 : 1;
}

// SCRATCH figure: ONE duet (SHA-256) cache-save + ONE MULTI-BLOCK cache-resume
// (120 B tail spills into a second block during the resume).  Figure
// transactions first so the waveform windows sit early in the VCD; the
// one-shot oracle verifies the digest afterwards.
int run_case2b_duet_fig(SharmonyDriver& drv, const TestOptions&) {
    const Mode m = Mode::SHA2_256;
    auto waitIdle = [&]() { for (int i = 0; i < 800 && drv.busy(); ++i) drv.tick(); };

    std::vector<uint8_t> pf(64), tt(120);
    for (size_t i = 0; i < pf.size(); ++i) pf[i] = uint8_t(i * 7 + 3);
    for (size_t i = 0; i < tt.size(); ++i) tt[i] = uint8_t(0x33 ^ (i * 5));

    // 1) cache-save the 1-block prefix (silent).
    drv.reset(); drv.setMode(m); drv.setOutReady(true);
    drv.setStateCache(true); drv.setStateSave(true); drv.setStateLoad(false);
    if (!drv.tryPulseStart(500)) return 1;
    drv.sendMessageDuetMirror(pf); drv.endMsg();
    drv.setStateSave(false);
    waitIdle();

    // 2) cache-resume + finalize the 120 B tail (multi-block resume).
    drv.setStateCache(true); drv.setStateLoad(true); drv.setStateSave(false);
    if (!drv.tryPulseStart(500)) return 1;
    drv.sendMessageDuetMirror(tt); drv.endMsg();
    auto dres = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000).second;
    drv.setStateLoad(false); drv.setStateCache(false);
    waitIdle();

    // 3) oracle (after the figure windows).
    std::vector<uint8_t> whole = pf; whole.insert(whole.end(), tt.begin(), tt.end());
    auto dref = hashDigestDuet(drv, m, whole);

    if (eq(dres, dref)) {
        std::cout << "[PASS] [case2b_duet_fig] duet cache-save + multi-block resume verified\n";
        return 0;
    }
    std::cerr << "[FAIL] [case2b_duet_fig]\n";
    dump("dref", dref); dump("dres", dres);
    return 1;
}

//-------------------------------------------------------------------------------------
// Midstate/cache corner-case batch.  Each item states its EXPECTED outcome; a
// result only counts as a failure when it contradicts the expectation
// (documented-GIGO items are OK when they produce a wrong digest, and flagged
// if they unexpectedly produce a right one).  Covers: cache survival across
// SHA-3 / invalidation by SHA-2, slot overwrite, streamed multi-block tails,
// the pad resume length-seed limit, cold resume, export backpressure, short
// state streams, and the non-aligned-save wedge guard (J/J2/J3).
//-------------------------------------------------------------------------------------
int midstateCornerBatch(SharmonyDriver& drv) {
    const Mode m = Mode::SHA2_512;
    int unexpected = 0;
    auto waitIdle = [&]() { for (int i = 0; i < 2000 && drv.busy(); ++i) drv.tick(); };
    auto item = [&](const char* tag, bool ok, const char* note) {
        if (ok) std::cout << "[PASS] [midstate] corner " << tag << "\n";
        else  { std::cerr << "[FAIL] [midstate] corner " << tag << " -- " << note << "\n";
                ++unexpected; }
    };

    // NO-RESET hash: run a full normal hash without touching resetn (so the
    // on-chip cache slot H_q is only affected by the DUT itself).
    auto hashNoReset = [&](Mode hm, const std::vector<uint8_t>& msg) {
        drv.setMode(hm); drv.setOutReady(true);
        drv.setStateLoad(false); drv.setStateSave(false); drv.setStateCache(false);
        if (!drv.tryPulseStart(500)) return std::vector<uint64_t>{};
        drv.sendMessageNative(msg); drv.endMsg();
        auto d = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(hm)), 8000).second;
        waitIdle();
        return d;
    };
    auto cacheSaveNR = [&](Mode cm, const std::vector<uint8_t>& data) {
        drv.setMode(cm); drv.setOutReady(true);
        drv.setStateCache(true); drv.setStateSave(true); drv.setStateLoad(false);
        if (!drv.tryPulseStart(500)) return false;
        drv.sendMessageNative(data); drv.endMsg();
        drv.setStateSave(false);
        waitIdle();
        return true;
    };
    auto cacheResumeNR = [&](Mode cm, const std::vector<uint8_t>& tail) {
        drv.setMode(cm); drv.setOutReady(true);
        drv.setStateCache(true); drv.setStateLoad(true); drv.setStateSave(false);
        std::vector<uint64_t> d;
        if (drv.tryPulseStart(500)) {
            drv.sendMessageNative(tail); drv.endMsg();
            d = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(cm)), 8000).second;
        }
        drv.setStateLoad(false); drv.setStateCache(false);
        waitIdle();
        return d;
    };

    std::vector<uint8_t> prefix(128), tail(37);
    for (size_t i = 0; i < prefix.size(); ++i) prefix[i] = uint8_t(i * 3 + 7);
    for (size_t i = 0; i < tail.size(); ++i)   tail[i]   = uint8_t(0x5A ^ i);
    std::vector<uint8_t> full = prefix; full.insert(full.end(), tail.begin(), tail.end());

    drv.reset();
    auto d_ok = hashNoReset(m, full);   // oracle (also leaves H_q dirty on purpose)

    // (former item A -- zeroize destroys the cache slot -- lives in
    //  zeroize_test.cpp as scenario Z10, where the zeroize coverage belongs.)

    //---------------------------------------------------------------------------------
    //  B. cache SURVIVES an intervening SHA-3 hash (H_q untouched)
    //---------------------------------------------------------------------------------
    drv.reset();
    cacheSaveNR(m, prefix);
    std::vector<uint8_t> other(200); for (size_t i = 0; i < 200; ++i) other[i] = uint8_t(i);
    (void)hashNoReset(Mode::SHA3_256, other);   // full SHA-3 txn in between
    auto dB = cacheResumeNR(m, tail);
    item("B cache-survives-sha3", eq(dB, d_ok),
         "SHA-3 uses R_q only; SHA-2 cache slot (H_q) must survive");

    //---------------------------------------------------------------------------------
    //  C. cache CLOBBERED by an intervening SHA-2 hash
    //---------------------------------------------------------------------------------
    drv.reset();
    cacheSaveNR(m, prefix);
    (void)hashNoReset(Mode::SHA2_384, other);   // SHA-2 rewrites H_q
    auto dC = cacheResumeNR(m, tail);
    item("C cache-invalidated-by-sha2", !eq(dC, d_ok),
         "intervening SHA-2 hash overwrites the single slot (documented GIGO)");

    //---------------------------------------------------------------------------------
    //  D. back-to-back cache-saves: 2nd save owns the slot
    //---------------------------------------------------------------------------------
    std::vector<uint8_t> prefixB(128); for (size_t i = 0; i < 128; ++i) prefixB[i] = uint8_t(0xC3 ^ (i * 11));
    std::vector<uint8_t> fullB = prefixB; fullB.insert(fullB.end(), tail.begin(), tail.end());
    drv.reset();
    auto d_okB = hashNoReset(m, fullB);
    drv.reset();
    cacheSaveNR(m, prefix);      // save A
    cacheSaveNR(m, prefixB);     // save B overwrites
    auto dD = cacheResumeNR(m, tail);
    item("D second-save-overwrites", eq(dD, d_okB), "resume yields B's chain, not A's");

    //---------------------------------------------------------------------------------
    //  E. STREAMED resume with multi-block tails
    //---------------------------------------------------------------------------------
    {
        int bad = 0;
        const size_t etails[] = {111, 112, 128, 300};
        for (size_t ts : etails) {
            std::vector<uint8_t> tt(ts); for (size_t i = 0; i < ts; ++i) tt[i] = uint8_t(0x77 ^ (i * 3));
            std::vector<uint8_t> wh = prefix; wh.insert(wh.end(), tt.begin(), tt.end());
            auto dr = hashDigest(drv, m, wh);
            auto ms = saveState(drv, m, prefix, 8, nullptr);
            auto dz = resumeDigest(drv, m, ms, tt);
            if (!eq(dz, dr)) { ++bad; std::cerr << "[midstate]   corner E sha512 tail=" << ts << " MISMATCH\n"; }
        }
        // SHA-3 (rate 136): tails across the rate boundary.
        const size_t etails3[] = {135, 136, 137, 272};
        for (size_t ts : etails3) {
            std::vector<uint8_t> tt(ts); for (size_t i = 0; i < ts; ++i) tt[i] = uint8_t(0x77 ^ (i * 3));
            std::vector<uint8_t> pf3(136); for (size_t i = 0; i < 136; ++i) pf3[i] = uint8_t(i * 5 + 1);
            std::vector<uint8_t> wh = pf3; wh.insert(wh.end(), tt.begin(), tt.end());
            auto dr = hashDigest(drv, Mode::SHA3_256, wh);
            auto ms = saveState(drv, Mode::SHA3_256, pf3, 25, nullptr);
            auto dz = resumeDigest(drv, Mode::SHA3_256, ms, tt);
            if (!eq(dz, dr)) { ++bad; std::cerr << "[midstate]   corner E sha3 tail=" << ts << " MISMATCH\n"; }
        }
        item("E streamed-multiblock-tails", bad == 0, "8 streamed resume tails across block/rate edges");
    }

    //---------------------------------------------------------------------------------
    //  F. 2-block streamed prefix: documents the length-seed limit
    //---------------------------------------------------------------------------------
    {
        std::vector<uint8_t> p2 = prefix; p2.insert(p2.end(), prefixB.begin(), prefixB.end());
        std::vector<uint8_t> wh = p2; wh.insert(wh.end(), tail.begin(), tail.end());
        auto dr = hashDigest(drv, m, wh);
        auto ms = saveState(drv, m, p2, 8, nullptr);       // MS after 2 blocks
        auto dz = resumeDigest(drv, m, ms, tail);
        item("F two-block-prefix-length-limit", !eq(dz, dr),
             "resume length seed assumes 1-block prefix (documented pad limit) -> wrong digest expected");
    }

    //---------------------------------------------------------------------------------
    //  G. COLD cache-resume (no save ever)
    //---------------------------------------------------------------------------------
    drv.reset();
    (void)hashNoReset(m, full);          // leaves H_q at some post-hash value
    auto dG = cacheResumeNR(m, tail);
    item("G cold-resume-no-hang", dG.size() == static_cast<size_t>(digestBeatsFor(m)),
         "resume without save = GIGO but must complete with a full (wrong) digest");
    item("G cold-resume-gigo", !eq(dG, d_ok), "and must not accidentally equal the real digest");

    //---------------------------------------------------------------------------------
    //  H. export under output backpressure
    //---------------------------------------------------------------------------------
    {
        auto ms_ref = saveState(drv, m, prefix, 8, nullptr);
        drv.reset(); drv.setMode(m);
        drv.setOutReady(false);                       // stall the export
        drv.setStateLoad(false); drv.setStateSave(true); drv.setStateCache(false);
        std::vector<uint64_t> ms_bp;
        if (drv.tryPulseStart(500)) {
            drv.sendMessageNative(prefix); drv.endMsg();
            for (int i = 0; i < 40; ++i) drv.tick();  // hold the stall
            drv.setOutReady(true);
            ms_bp = drv.tryCollectBeats(8, 8000).second;
        }
        drv.setStateSave(false); waitIdle();
        item("H export-backpressure", eq(ms_bp, ms_ref),
             "stalled-then-released state export == unstalled export");
    }

    //---------------------------------------------------------------------------------
    //  I. SHORT state stream (7 of 8 MS words, then message)
    //---------------------------------------------------------------------------------
    {
        auto ms = saveState(drv, m, prefix, 8, nullptr);
        drv.reset(); drv.setMode(m); drv.setOutReady(true);
        drv.setStateLoad(true); drv.setStateSave(false);
        std::vector<uint64_t> dI;
        if (drv.tryPulseStart(500)) {
            for (int i = 0; i < 7; ++i) (void)drv.trySendBeat(ms[i], 8, 0b00, 2000);
            drv.sendMessageNative(tail);  // 1st tail beat consumed as 8th MS word
            drv.endMsg();
            dI = drv.tryCollectBeats(static_cast<size_t>(digestBeatsFor(m)), 8000).second;
        }
        drv.setStateLoad(false); waitIdle();
        item("I short-state-stream-no-hang", !drv.busy(),
             "under-filled state load = GIGO but engine must reach idle");
        item("I short-state-stream-gigo", !eq(dI, d_ok), "and digest must be wrong");
    }

    //---------------------------------------------------------------------------------
    //  J. NON-block-aligned cache-save prefix
    //---------------------------------------------------------------------------------
    {
        std::vector<uint8_t> odd(100); for (size_t i = 0; i < 100; ++i) odd[i] = uint8_t(i + 9);
        drv.reset();
        bool started = cacheSaveNR(m, odd);           // 100 B: not block-aligned
        bool idle_ok = started && !drv.busy();
        std::cout << "[midstate]   corner J diag: save started=" << started
                  << " busy_after_save=" << drv.busy() << "\n";
        auto dJ = cacheResumeNR(m, tail);
        std::cout << "[midstate]   corner J diag: resume_beats=" << dJ.size()
                  << " busy_after_resume=" << drv.busy() << "\n";
        item("J odd-save-no-hang", idle_ok && !drv.busy(),
             "non-aligned cache-save = GIGO but must not hang");
        item("J odd-save-gigo", !eq(dJ, d_ok), "and resume digest must be wrong");
        // FINDING follow-up: is the wedge recoverable by zeroize (no reset)?
        drv.setZeroize(true); drv.tick(); drv.setZeroize(false);
        waitIdle();
        bool unwedged = !drv.busy();
        auto dJ2 = hashNoReset(m, full);
        item("J zeroize-recovers-wedge", unwedged && eq(dJ2, d_ok),
             "zeroize must clear the wedge and restore normal operation");
        // Same pad branch without the cache: streamed state_save, odd prefix.
        drv.reset(); drv.setMode(m); drv.setOutReady(true);
        drv.setStateSave(true); drv.setStateLoad(false); drv.setStateCache(false);
        if (drv.tryPulseStart(500)) { drv.sendMessageNative(odd); drv.endMsg(); }
        waitIdle();
        item("J2 odd-streamed-save-no-hang", !drv.busy(),
             "streamed state_save with non-aligned prefix must not hang");
        drv.setStateSave(false);

        //-----------------------------------------------------------------------------
        //  J3. non-aligned save SWEEP: misalignment flavors x modes
        //-----------------------------------------------------------------------------
        // Probe: save `nbytes` (cache or streamed), report hang; cache saves
        // must additionally stay SILENT (no output beats).
        auto oddProbe = [&](Mode pm, size_t nbytes, bool use_cache, bool duet,
                            const char* nm) {
            std::vector<uint8_t> d(nbytes);
            for (size_t i = 0; i < nbytes; ++i) d[i] = uint8_t(i + 9);
            drv.reset(); drv.setMode(pm); drv.setOutReady(true);
            drv.setStateCache(use_cache); drv.setStateSave(true); drv.setStateLoad(false);
            bool st = drv.tryPulseStart(500);
            if (st) { if (duet) drv.sendMessageDuetMirror(d); else drv.sendMessageNative(d);
                      drv.endMsg(); }
            drv.setStateSave(false);
            uint64_t out_beats = 0;
            for (int i = 0; i < 2000 && drv.busy(); ++i) {
                drv.tick();
                if (drv.outputValid()) out_beats++;
            }
            bool hang   = drv.busy();
            bool silent = (out_beats == 0);
            std::cout << "[midstate]   corner J3 " << nm << " bytes=" << nbytes
                      << (use_cache ? " cache" : " streamed")
                      << ": " << (hang ? "WEDGED" : "idle")
                      << (use_cache ? (silent ? " silent" : " LEAKED") : "") << "\n";
            // unwedge for the next probe
            drv.setZeroize(true); drv.tick(); drv.setZeroize(false);
            waitIdle();
            drv.setStateCache(false);
            return !hang && (!use_cache || silent);
        };
        int j3_bad = 0;
        //   8 B  = 1 word only            (final on word 1)
        //  96 B  = 12 full words, bytes=8 (final mid-block, full last beat)
        // 100 B  = partial word mid-block (final mid-block, partial beat)
        // 127 B  = partial word AT block boundary (word 16, bytes=7)
        j3_bad += !oddProbe(m, 8,   true,  false, "sha512");
        j3_bad += !oddProbe(m, 96,  true,  false, "sha512");
        j3_bad += !oddProbe(m, 96,  false, false, "sha512");
        j3_bad += !oddProbe(m, 100, false, false, "sha512");
        j3_bad += !oddProbe(m, 127, true,  false, "sha512");
        j3_bad += !oddProbe(Mode::SHA2_256, 30, true, true, "sha256duet");
        j3_bad += !oddProbe(Mode::SHA3_256, 100, false, false, "sha3_256");
        item("J3 odd-save-sweep", j3_bad == 0,
             "all non-aligned save flavors: no wedge, cache stays silent");
    }

    std::cout << "[midstate] corner batch: " << (unexpected == 0 ? "ALL EXPECTATIONS MET"
                                                          : "UNEXPECTED RESULTS")
              << " (" << unexpected << " unexpected)\n";
    return unexpected == 0 ? 0 : 1;
}

//-------------------------------------------------------------------------------------
// REGRESSION: cache pins asserted in SHA-3 mode (mode-wins guard).
// The internal cache is SHA-2-only (slot = H_q, which SHA-3 never writes).
// With the fix, SHA-3 IGNORES the cache pins and matches the pad's view:
//   S1/S2  SHA3-256 cache-SAVE  (32/136 B): benign silent no-op -- engine
//          idles, emits nothing (cache_save -> CORE_IDLE, mode-agnostic).
//   S3/S4  SHA3-256 cache-RESUME (32/272 B): degrades to a PLAIN SHA-3 hash
//          of the streamed message == hashDigest(SHA3-256, msg). No wedge.
// Pre-fix S3 wedged (short msg) and S4 gave a wrong digest.
//-------------------------------------------------------------------------------------
int run_sha3cache(SharmonyDriver& drv, const TestOptions&) {
    const Mode m = Mode::SHA3_256;
    const size_t nbeats = static_cast<size_t>(digestBeatsFor(m));
    int bad = 0;

    // expect: 0 = silent no-op (save), 1 = plain-hash (resume)
    auto probe = [&](const char* nm, bool save, bool load, size_t nbytes, int expect) {
        std::vector<uint8_t> msg(nbytes);
        for (size_t i = 0; i < nbytes; ++i) msg[i] = uint8_t(i * 5 + 1);

        drv.setStateCache(false);
        auto d_ok = hashDigest(drv, m, msg);            // plain-hash oracle (resets)

        drv.reset(); drv.setMode(m); drv.setOutReady(true);
        drv.setStateCache(true); drv.setStateSave(save); drv.setStateLoad(load);
        bool accepted = drv.tryPulseStart(500) && drv.busy();
        std::vector<uint64_t> d;
        if (accepted) {
            drv.sendMessageNative(msg);
            drv.endMsg();
            d = drv.tryCollectBeats(nbeats, 6000).second;
        }
        drv.setStateSave(false); drv.setStateLoad(false);
        for (int i = 0; i < 2000 && drv.busy(); ++i) drv.tick();
        bool hang = drv.busy();

        bool ok;
        const char* verdict;
        if (expect == 1) {                       // resume -> plain hash
            ok = !hang && eq(d, d_ok);
            verdict = ok ? "PLAIN-HASH (correct)" : "NOT a clean plain hash";
        } else {                                 // save -> silent no-op
            ok = !hang && d.empty();
            verdict = ok ? "silent no-op" : "unexpected output/hang";
        }
        std::cout << "[sha3cache] " << nm << " (" << nbytes << " B): "
                  << (hang ? "WEDGED " : "idle ") << "beats=" << d.size()
                  << " -> " << verdict << "\n";

        // recovery: zeroize, then a plain hash must still be correct
        drv.setZeroize(true); drv.tick(); drv.setZeroize(false);
        for (int i = 0; i < 2000 && drv.busy(); ++i) drv.tick();
        drv.setStateCache(false);
        auto d_after = hashDigest(drv, m, msg);
        bool recovered = !drv.busy() && eq(d_after, d_ok);
        if (!ok || !recovered) {
            ++bad;
            std::cerr << "[FAIL] [sha3cache] " << nm
                      << (ok ? "" : " (behavior)")
                      << (recovered ? "" : " (recovery)") << "\n";
        }
    };

    probe("S1 sha3 cache-save",   true,  false, 32,  0);
    probe("S2 sha3 cache-save",   true,  false, 136, 0);
    probe("S3 sha3 cache-resume", false, true,  32,  1);
    probe("S4 sha3 cache-resume", false, true,  272, 1);

    std::cout << "[sha3cache] SUMMARY: " << (bad == 0 ? "ALL PASS (SHA-3 cache "
                 "pins -> plain hash / silent no-op)" : "FAILURES") << "\n";
    return bad == 0 ? 0 : 1;
}

}  // namespace

REGISTER_TEST("midstate", run_midstate);
REGISTER_TEST("midstate_cache", run_midstate_cache);
REGISTER_TEST("case2b", run_case2b);
REGISTER_TEST("case2b_duet_fig", run_case2b_duet_fig);
REGISTER_TEST("sha3cache", run_sha3cache);
