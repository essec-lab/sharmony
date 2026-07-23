///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "common/MonteTest.hpp"

namespace sharmony {
static int run_sha384_monte(SharmonyDriver& drv, const TestOptions& opts) {
    return runMonte(drv, opts, Mode::SHA2_384, MonteFamily::Sha2,
                    "tb/src/tests/data/SHA384Monte.rsp", "sha384_monte");
}
REGISTER_TEST("sha384_monte", run_sha384_monte);
}
