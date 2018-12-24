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

TEST(rc_prf, constrain)
{
    constexpr uint8_t                  test_depth = 3;
    std::array<uint8_t, kRCPrfKeySize> k{
        {0x00}}; // fixed key for easy debugging and bug reproducing
    sse::crypto::RCPrf<16> rc_prf(sse::crypto::Key<kRCPrfKeySize>(k.data()),
                                  test_depth);

    for (uint64_t min = 0; min < sse::crypto::RCPrfBase::leaf_count(test_depth);
         min++) {
        for (uint64_t max = min;
             max < sse::crypto::RCPrfBase::leaf_count(test_depth);
             max++) {
            auto constrained_prf = rc_prf.constrain(min, max);
            for (uint64_t leaf = min; leaf <= max; leaf++) {
                auto out             = rc_prf.eval(leaf);
                auto out_constrained = constrained_prf.eval(leaf);
                ASSERT_EQ(out, out_constrained);
            }
        }
    }
}