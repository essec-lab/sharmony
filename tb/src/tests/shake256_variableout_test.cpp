///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "common/ShakeXofTest.hpp"
namespace sharmony {
static int run_shake256_variableout(SharmonyDriver& drv, const TestOptions& opts) {
    return runShakeVariableOut(drv, opts, Mode::SHAKE256,
              "tb/src/tests/data/SHAKE256VariableOut.rsp",
              "shake256_variableout");
}
REGISTER_TEST("shake256_variableout", run_shake256_variableout);
}  // namespace sharmony
