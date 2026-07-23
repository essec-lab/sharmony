///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "common/HashKatTest.hpp"

namespace sharmony {
static int run_sha512_shortmsg(SharmonyDriver& drv, const TestOptions& opts) {
    return runHashKat(drv, opts, Mode::SHA2_512,
                      "tb/src/tests/data/SHA512ShortMsg.rsp", "sha512_shortmsg");
}
REGISTER_TEST("sha512_shortmsg", run_sha512_shortmsg);
}
