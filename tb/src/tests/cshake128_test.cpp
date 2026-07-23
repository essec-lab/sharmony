///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "common/CShakeKatTest.hpp"

namespace sharmony {

static int run_cshake128(SharmonyDriver& drv, const TestOptions& opts) {
    return runCShakeKat(drv, opts, Mode::CSHAKE128,
                        "tb/src/tests/data/cSHAKE128.rsp", "cshake128");
}

REGISTER_TEST("cshake128", run_cshake128);

}  // namespace sharmony
