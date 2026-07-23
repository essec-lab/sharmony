///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Aggregate wrapper: run the full all-mode regression suite.
//
///////////////////////////////////////////////////////////////////////////////////////

#include "common/AggregateRunner.hpp"

namespace sharmony {

static int run_nightly(SharmonyDriver& drv, const TestOptions& opts) {
    return runAggregateTests(drv, opts, nightlyAllModeTests(), "nightly");
}

REGISTER_TEST("nightly", run_nightly);

}  // namespace sharmony
