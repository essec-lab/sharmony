///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "common/ShakeKatTest.hpp"

namespace sharmony {
static int run_shake128_longmsg(SharmonyDriver& drv, const TestOptions& opts) {
    return runShakeKat(drv, opts, Mode::SHAKE128,
                       "tb/src/tests/data/SHAKE128LongMsg.rsp", "shake128_longmsg");
}
REGISTER_TEST("shake128_longmsg", run_shake128_longmsg);
}
