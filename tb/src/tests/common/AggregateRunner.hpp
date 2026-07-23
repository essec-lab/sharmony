///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Shared aggregate-test runner used by the all-mode wrapper tests.
// The wrapper .cpp files under tests/ give Makefile-visible names such as
// shortmsg, longmsg, and nightly.
//
///////////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "../../SharmonyDriver.hpp"
#include "../../TestRegistry.hpp"

#include <string>
#include <vector>

namespace sharmony {

const std::vector<std::string>& shortMsgAllModeTests();
const std::vector<std::string>& longMsgAllModeTests();
const std::vector<std::string>& monteAllModeTests();
const std::vector<std::string>& cshakeAllModeTests();
const std::vector<std::string>& protocolAllModeTests();
std::vector<std::string> nightlyAllModeTests();

int runAggregateTests(SharmonyDriver& drv,
                      const TestOptions& opts,
                      const std::vector<std::string>& tests,
                      const std::string& label);

}  // namespace sharmony
