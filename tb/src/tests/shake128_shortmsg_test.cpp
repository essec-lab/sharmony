///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "common/ShakeKatTest.hpp"

namespace sharmony {
static int run_shake128_shortmsg(SharmonyDriver& drv, const TestOptions& opts) {
    return runShakeKat(drv, opts, Mode::SHAKE128,
                       "tb/src/tests/data/SHAKE128ShortMsg.rsp", "shake128_shortmsg");
}
REGISTER_TEST("shake128_shortmsg", run_shake128_shortmsg);
}
