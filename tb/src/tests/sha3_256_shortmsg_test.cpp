///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "common/HashKatTest.hpp"

namespace sharmony {
static int run_sha3_256_shortmsg(SharmonyDriver& drv, const TestOptions& opts) {
    return runHashKat(drv, opts, Mode::SHA3_256,
                      "tb/src/tests/data/SHA3_256ShortMsg.rsp", "sha3_256_shortmsg");
}
REGISTER_TEST("sha3_256_shortmsg", run_sha3_256_shortmsg);
}
