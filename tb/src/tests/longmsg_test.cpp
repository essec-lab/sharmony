///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Aggregate wrapper: run every LongMsg KAT across all hash modes/variants.
//
///////////////////////////////////////////////////////////////////////////////////////

#include "common/AggregateRunner.hpp"

namespace sharmony {

static int run_longmsg(SharmonyDriver& drv, const TestOptions& opts) {
    return runAggregateTests(drv, opts, longMsgAllModeTests(), "longmsg");
}

REGISTER_TEST("longmsg", run_longmsg);

}  // namespace sharmony
