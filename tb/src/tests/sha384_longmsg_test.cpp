///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "common/HashKatTest.hpp"

namespace sharmony {
static int run_sha384_longmsg(SharmonyDriver& drv, const TestOptions& opts) {
    return runHashKat(drv, opts, Mode::SHA2_384,
                      "tb/src/tests/data/SHA384LongMsg.rsp", "sha384_longmsg");
}
REGISTER_TEST("sha384_longmsg", run_sha384_longmsg);
}
