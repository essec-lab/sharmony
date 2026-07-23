///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Lightweight C++ test registry. Each test is a function that takes a
// SharmonyDriver and TestOptions and returns 0 on success, non-zero on
// failure. Tests register themselves at startup via REGISTER_TEST(name, fn).
//
///////////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>

namespace sharmony {

class SharmonyDriver;

struct TestOptions {
    std::string rsp_path;     // --rsp <path>
    std::string vcd_path;     // --vcd <path>
    int         verbosity = 0;
    int         max_vectors = 0;   // 0 = unlimited; cap for quick local runs
    std::string mode_filter;       // --mode <NAME>; empty = sweep all
    double      freq_mhz = 132.0;  // --freq-mhz <MHz>; default 132 (post-synth Fmax)
    bool figure_trace = false;
};

using TestFn = std::function<int(SharmonyDriver&, const TestOptions&)>;

class TestRegistry {
public:
    static TestRegistry& instance();

    void registerTest(const std::string& name, TestFn fn);
    const TestFn* find(const std::string& name) const;
    std::vector<std::string> names() const;

private:
    std::map<std::string, TestFn> tests_;
};

// Helper for static-init registration.
struct TestRegistrar {
    TestRegistrar(const std::string& name, TestFn fn) {
        TestRegistry::instance().registerTest(name, std::move(fn));
    }
};

#define REGISTER_TEST(name, fn) \
    static ::sharmony::TestRegistrar _reg_##fn(name, fn)

}  // namespace sharmony
