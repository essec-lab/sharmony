///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Entry point for the Verilator C++ testbench flow.
//
// Usage (from the repo root; default .rsp paths are repo-root-relative):
//   ./tb/work/obj_dir/Vsharmony_verilator_wrapper --test shortmsg
//   ./tb/work/obj_dir/Vsharmony_verilator_wrapper --test sha512_shortmsg --rsp <path>
//   ./tb/work/obj_dir/Vsharmony_verilator_wrapper --list-tests
//   ./tb/work/obj_dir/Vsharmony_verilator_wrapper --test shortmsg --vcd waveform.vcd
//
// Exit code: 0 on success, 1 on test failure, 2 on usage error.
//
///////////////////////////////////////////////////////////////////////////////////////

#include "SharmonyDriver.hpp"
#include "TestRegistry.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using namespace sharmony;

static void usage(const char* prog) {
    std::cerr <<
        "usage: " << prog << " [options]\n"
        "  --test <name>       Run the named test (required unless --list-tests)\n"
        "  --rsp <path>        Path to a NIST .rsp vector file for KAT tests\n"
        "  --vcd <path>        Dump VCD waveform to <path>\n"
        "  --max-vectors <n>   Cap vectors processed (0 = unlimited; default 0)\n"
        "  --figure-trace      Emit one clean transaction for documentation figures\n"
        "  --verbose <n>       Verbosity 0..2 (default 0)\n"
        "  --mode <NAME>       Single-mode filter for scenario tests\n"
        "                      (e.g. HASH_SHA2_256, XOF_SHAKE128); default = sweep all\n"
        "  --freq-mhz <MHz>   Clock frequency for performance reports (default 132)\n"
        "  --list-tests        Print available tests and exit\n"
        "\nExit code: 0 if test passes, 1 if it fails, 2 on usage error.\n";
}

int main(int argc, char** argv) {
    std::string test_name;
    TestOptions opts;
    bool list_tests = false;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto need = [&](const char* what) {
            if (i + 1 >= argc) {
                std::cerr << "missing argument for " << what << "\n";
                std::exit(2);
            }
            return std::string(argv[++i]);
        };
        if      (a == "--test")        test_name        = need("--test");
        else if (a == "--rsp")         opts.rsp_path    = need("--rsp");
        else if (a == "--vcd")         opts.vcd_path    = need("--vcd");
        else if (a == "--max-vectors") opts.max_vectors = std::atoi(need("--max-vectors").c_str());
        else if (a == "--verbose")     opts.verbosity   = std::atoi(need("--verbose").c_str());
        else if (a == "--mode")        opts.mode_filter = need("--mode");
        else if (a == "--freq-mhz")    opts.freq_mhz    = std::atof(need("--freq-mhz").c_str());
        else if (a == "--figure-trace") opts.figure_trace = true;
        else if (a == "--list-tests")  list_tests       = true;
        else if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
        // Unknown args pass through (Verilator may consume some).
    }

    auto& reg = TestRegistry::instance();

    if (list_tests) {
        std::cout << "Available tests:\n";
        for (const auto& n : reg.names()) std::cout << "  " << n << "\n";
        return 0;
    }

    if (test_name.empty()) {
        std::cerr << "--test <name> is required (or use --list-tests)\n";
        usage(argv[0]);
        return 2;
    }

    const auto* fn_ptr = reg.find(test_name);
    if (!fn_ptr) {
        std::cerr << "[FAIL] unknown test '" << test_name << "'\n";
        std::cerr << "Available:\n";
        for (const auto& n : reg.names()) std::cerr << "  " << n << "\n";
        return 2;
    }

    SharmonyDriver drv(argc, argv, opts.vcd_path);

    int rc = 1;
    try {
        rc = (*fn_ptr)(drv, opts);
    } catch (const TimeoutError& e) {
        std::cerr << "[FAIL] " << test_name << ": timeout: " << e.what() << "\n";
        rc = 1;
    } catch (const std::exception& e) {
        std::cerr << "[FAIL] " << test_name << ": exception: " << e.what() << "\n";
        rc = 1;
    }

    // Autotools-style skip convention: rc == 77 means "test deliberately
    // skipped" (e.g. unported stub). We print [SKIP] and return 0 to the OS
    // so CI doesn't false-fail, but the [PASS] line is NOT emitted.
    const bool skipped = (rc == 77);

    if (skipped) {
        std::cout << "[SKIP] " << test_name << "\n";
        std::cout << "Summary: 0 passed, 0 failed, 1 skipped\n";
    } else if (rc == 0) {
        std::cout << "[PASS] " << test_name << "\n";
        std::cout << "Summary: 1 passed, 0 failed\n";
    } else {
        std::cout << "[FAIL] " << test_name << " (rc=" << rc << ")\n";
        std::cout << "Summary: 0 passed, 1 failed\n";
    }

    return skipped ? 0 : rc;
}
