///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Shared implementation for aggregate all-mode Verilator tests.
//
// Aggregate tests dispatch through the existing TestRegistry so they reuse the
// same per-mode KAT and Monte tests that can still be run individually with
// --test <name>.
//
// Aggregate tests intentionally ignore opts.rsp_path: each child test needs its
// own default .rsp file. Verbosity and max_vectors are still propagated.
//
///////////////////////////////////////////////////////////////////////////////////////

#include "AggregateRunner.hpp"

#include <exception>
#include <iostream>
#include <string>
#include <vector>

namespace sharmony {

const std::vector<std::string>& shortMsgAllModeTests() {
    static const std::vector<std::string> tests = {
        "sha224_shortmsg",
        "sha256_shortmsg",
        "sha384_shortmsg",
        "sha512_shortmsg",
        "sha512_224_shortmsg",
        "sha512_256_shortmsg",
        "sha3_224_shortmsg",
        "sha3_256_shortmsg",
        "sha3_384_shortmsg",
        "sha3_512_shortmsg",
        "shake128_shortmsg",
        "shake256_shortmsg",

        // SHAKE variable-output vectors are short-message style XOF checks.
        // Keep them before the SHA-224/SHA-256 duet-mode checks that are run
        // directly by shortmsg_test.cpp.
        "shake128_variableout",
        "shake256_variableout",
    };
    return tests;
}

const std::vector<std::string>& longMsgAllModeTests() {
    static const std::vector<std::string> tests = {
        "sha224_longmsg",
        "sha256_longmsg",
        "sha384_longmsg",
        "sha512_longmsg",
        "sha512_224_longmsg",
        "sha512_256_longmsg",
        "sha3_224_longmsg",
        "sha3_256_longmsg",
        "sha3_384_longmsg",
        "sha3_512_longmsg",
        "shake128_longmsg",
        "shake256_longmsg",
    };
    return tests;
}

const std::vector<std::string>& monteAllModeTests() {
    static const std::vector<std::string> tests = {
        "sha224_monte",
        "sha256_monte",
        "sha384_monte",
        "sha512_monte",
        "sha512_224_monte",
        "sha512_256_monte",
        "sha3_224_monte",
        "sha3_256_monte",
        "sha3_384_monte",
        "sha3_512_monte",
        "shake128_monte",
        "shake256_monte",
    };
    return tests;
}

const std::vector<std::string>& cshakeAllModeTests() {
    static const std::vector<std::string> tests = {
        "cshake128",
        "cshake256",
    };
    return tests;
}

const std::vector<std::string>& protocolAllModeTests() {
    // `reset` coverage now runs inside `interface` (runMergedResetScenarios);
    // the standalone reset test was removed.
    static const std::vector<std::string> tests = {
        "error",
        "interface",
        "midstate",       // save/resume round-trips, resume-finalize, caching
        "zeroize",        // liga's zeroize/reset-window suite
        "zeroize_scrub",  // sensitive-register scrub check
    };
    return tests;
}

std::vector<std::string> nightlyAllModeTests() {
    std::vector<std::string> tests;
    const auto append = [&tests](const std::vector<std::string>& src) {
        tests.insert(tests.end(), src.begin(), src.end());
    };

    // Dispatch the `shortmsg` aggregate itself (not its child list) so the
    // SHA-224/SHA-256 duet-mode cross-lane KATs it runs on top of the children
    // are part of nightly.
    tests.push_back("shortmsg");
    append(longMsgAllModeTests());
    append(monteAllModeTests());
    append(cshakeAllModeTests());
    append(protocolAllModeTests());
    return tests;
}

static TestOptions childOptions(const TestOptions& opts) {
    TestOptions child = opts;
    child.rsp_path.clear();
    return child;
}

int runAggregateTests(SharmonyDriver& drv,
                      const TestOptions& opts,
                      const std::vector<std::string>& tests,
                      const std::string& label) {
    auto& reg = TestRegistry::instance();
    TestOptions child_opts = childOptions(opts);

    if (!opts.rsp_path.empty()) {
        std::cout << "[" << label << "] ignoring --rsp '" << opts.rsp_path
                  << "' because aggregate tests use per-child default RSP files\n";
    }

    int pass = 0;
    int fail = 0;
    int missing = 0;
    int skipped = 0;

    std::cout << "[" << label << "] running " << tests.size()
              << " child tests\n";

    for (const auto& name : tests) {
        const auto* fn = reg.find(name);
        if (!fn) {
            std::cerr << "[FAIL] " << label << ": child test '" << name
                      << "' is not registered\n";
            missing++;
            fail++;
            continue;
        }

        std::cout << "[" << label << "] BEGIN " << name << "\n";

        int rc = 1;
        try {
            rc = (*fn)(drv, child_opts);
        } catch (const TimeoutError& e) {
            std::cerr << "[FAIL] " << label << ": " << name
                      << ": timeout: " << e.what() << "\n";
            rc = 1;
        } catch (const std::exception& e) {
            std::cerr << "[FAIL] " << label << ": " << name
                      << ": exception: " << e.what() << "\n";
            rc = 1;
        }

        if (rc == 0) {
            pass++;
            std::cout << "[" << label << "] PASS " << name << "\n";
        } else if (rc == 77) {
            skipped++;
            std::cout << "[" << label << "] SKIP " << name << "\n";
        } else {
            fail++;
            std::cout << "[" << label << "] FAIL " << name
                      << " (rc=" << rc << ")\n";
        }
    }

    std::cout << "[" << label << "] summary: "
              << pass << " passed, "
              << fail << " failed, "
              << skipped << " skipped";
    if (missing > 0) {
        std::cout << ", " << missing << " missing";
    }
    std::cout << "\n";

    return fail == 0 ? 0 : 1;
}

}  // namespace sharmony
