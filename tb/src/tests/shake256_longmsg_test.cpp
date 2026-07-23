///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "common/ShakeKatTest.hpp"

namespace sharmony {
static int run_shake256_longmsg(SharmonyDriver& drv, const TestOptions& opts) {
    return runShakeKat(drv, opts, Mode::SHAKE256,
                       "tb/src/tests/data/SHAKE256LongMsg.rsp", "shake256_longmsg");
}
REGISTER_TEST("shake256_longmsg", run_shake256_longmsg);
}
