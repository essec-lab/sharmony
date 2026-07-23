///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// Shared logic for SHA-2 and SHA-3 known-answer-test (KAT) flows that read a
// NIST .rsp file with Len / Msg / MD fields. Per-mode tests are 5-line
// wrappers that just call runHashKat() with the right mode and default path.
//
///////////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "../../SharmonyDriver.hpp"
#include "../../TestRegistry.hpp"
#include <string>

namespace sharmony {

// Run a Len/Msg/MD-style KAT against the DUT.
//   mode         - hash mode under test
//   default_rsp  - default path used when opts.rsp_path is empty
//   testlabel    - display name in log lines, e.g. "sha256_shortmsg"
int runHashKat(SharmonyDriver& drv,
               const TestOptions& opts,
               Mode mode,
               const std::string& default_rsp,
               const std::string& testlabel);

}  // namespace sharmony
