//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2017 Raphael Bost
//
// This file is part of libsse_crypto.
//
// libsse_crypto is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// libsse_crypto is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with libsse_crypto.  If not, see <http://www.gnu.org/licenses/>.
//

#include <sse/crypto/random.hpp>
#include <sse/crypto/rcprf.hpp>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>

#include "gtest/gtest.h"

constexpr size_t kRCPrfKeySize = 32;

TEST(rc_prf, basic)
{
    constexpr uint8_t               test_depth = 5;
    sse::crypto::Key<kRCPrfKeySize> k;
    sse::crypto::RCPrf<16>          rc_prf(std::move(k), test_depth);

    for (size_t i = 0; i < (1UL << test_depth); i++) {
        auto out = rc_prf.eval(i);
    }
}