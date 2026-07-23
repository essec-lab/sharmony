///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "TestRegistry.hpp"

namespace sharmony {

TestRegistry& TestRegistry::instance() {
    static TestRegistry r;
    return r;
}

void TestRegistry::registerTest(const std::string& name, TestFn fn) {
    tests_[name] = std::move(fn);
}

const TestFn* TestRegistry::find(const std::string& name) const {
    auto it = tests_.find(name);
    return (it == tests_.end()) ? nullptr : &it->second;
}

std::vector<std::string> TestRegistry::names() const {
    std::vector<std::string> v;
    v.reserve(tests_.size());
    for (const auto& kv : tests_) v.push_back(kv.first);
    return v;
}

}  // namespace sharmony
