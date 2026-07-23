///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Aggregate wrapper: run every ShortMsg KAT across all hash modes/variants.
//
// This also runs the SHA-224/SHA-256 duet-mode cross-lane ShortMsg coverage,
// so the separate sha224_duetmode / sha256_duetmode tests are no longer needed
// as standalone regression targets.
//
///////////////////////////////////////////////////////////////////////////////////////

#include "common/AggregateRunner.hpp"
#include "common/HashKatPairDuetTest.hpp"

namespace sharmony {

static int run_shortmsg(SharmonyDriver& drv, const TestOptions& opts) {
    int rc = 0;

    rc |= runAggregateTests(drv, opts, shortMsgAllModeTests(), "shortmsg");

    rc |= runDuetXLaneKat(drv, opts, Mode::SHA2_224,
                          "tb/src/tests/data/SHA224ShortMsg.rsp",
                          "sha224_duetmode");

    rc |= runDuetXLaneKat(drv, opts, Mode::SHA2_256,
                          "tb/src/tests/data/SHA256ShortMsg.rsp",
                          "sha256_duetmode");

    return rc;
}

REGISTER_TEST("shortmsg", run_shortmsg);

}  // namespace sharmony
