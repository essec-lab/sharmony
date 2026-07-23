///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// SHAKE KAT runner. Format is similar to SHA-2/3 .rsp files except the
// expected output is named "Output" (handled identically by the parser) and
// the output length comes from "[Outputlen = N]" headers - but for this
// starter we only check the first 16 bytes (2 beats). Vectors with Output
// shorter than 16 bytes are skipped.
//
///////////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "../../SharmonyDriver.hpp"
#include "../../TestRegistry.hpp"
#include <string>

namespace sharmony {

int runShakeKat(SharmonyDriver& drv,
                const TestOptions& opts,
                Mode mode,
                const std::string& default_rsp,
                const std::string& testlabel);

}  // namespace sharmony
