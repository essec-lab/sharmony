///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "common/HashKatDuetTest.hpp"

namespace sharmony {
static int run_sha256_shortmsg(SharmonyDriver& drv, const TestOptions& opts) {
    return runHashKatDuet(drv, opts, Mode::SHA2_256,
                          "tb/src/tests/data/SHA256ShortMsg.rsp", "sha256_shortmsg");
}
REGISTER_TEST("sha256_shortmsg", run_sha256_shortmsg);
}
