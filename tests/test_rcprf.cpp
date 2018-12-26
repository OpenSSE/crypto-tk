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
    constexpr uint8_t                  test_depth = 7;
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

// Exceptions that should be raised by using the normal APIs
TEST(rc_prf, eval_constrain_exceptions)
{
    constexpr uint8_t                  test_depth = 7;
    std::array<uint8_t, kRCPrfKeySize> k{{0x00}};
    sse::crypto::RCPrf<16> rc_prf(sse::crypto::Key<kRCPrfKeySize>(k.data()),
                                  test_depth);

    // Exceptions raised by RCPRF::eval
    EXPECT_THROW(rc_prf.eval(1UL << (test_depth + 1)), std::out_of_range);
    EXPECT_THROW(rc_prf.eval(1UL << test_depth), std::out_of_range);

    // Exceptions raised by RCPrf::constrain
    EXPECT_THROW(rc_prf.constrain(3, 2), std::invalid_argument);
    EXPECT_THROW(rc_prf.constrain(0, 1UL << test_depth), std::out_of_range);

    uint64_t range_min = 4, range_max = 9;
    auto     constrained_rc_prf = rc_prf.constrain(range_min, range_max);

    // Exceptions raised by ConstrainedRCPrf::eval
    EXPECT_THROW(constrained_rc_prf.eval(range_min - 1), std::out_of_range);
    EXPECT_THROW(constrained_rc_prf.eval(range_max + 1), std::out_of_range);

    // Exceptions raised by ConstrainedRCPrfLeafElement::eval
    std::array<uint8_t, 16> buffer = sse::crypto::random_bytes<uint8_t, 16>();
    sse::crypto::ConstrainedRCPrfLeafElement<16> leaf(buffer, test_depth, 1);
    EXPECT_THROW(leaf.eval(0), std::out_of_range);
    EXPECT_THROW(leaf.eval(2), std::out_of_range);

    // Exceptions raised by ConstrainedRCPrfInnerElement::eval
    range_min              = 4;
    range_max              = 7;
    uint8_t subtree_height = 3;

    sse::crypto::ConstrainedRCPrfInnerElement<16> elt(
        sse::crypto::Key<kRCPrfKeySize>(),
        test_depth,
        subtree_height,
        range_min,
        range_max);
    EXPECT_THROW(elt.eval(range_min - 1), std::out_of_range);
    EXPECT_THROW(elt.eval(range_max + 1), std::out_of_range);
}

// Exceptions raised by the constructors
TEST(rc_prf, constructors_exceptions)
{
    // Exceptions raised the RCPrf constructor

    EXPECT_THROW(
        sse::crypto::RCPrf<16> rc_prf(sse::crypto::Key<kRCPrfKeySize>(), 0),
        std::invalid_argument);

    EXPECT_THROW(
        sse::crypto::RCPrf<16> rc_prf(sse::crypto::Key<kRCPrfKeySize>(), 70),
        std::invalid_argument);

    // Exceptions raised the ConstrainedRCPrfInnerElement constructor

    constexpr uint64_t range_min      = 0;
    constexpr uint64_t range_max      = 3;
    constexpr uint8_t  subtree_height = 3;
    constexpr uint8_t  tree_height    = subtree_height + 1;
    static_assert(
        range_max - range_min + 1
            == sse::crypto::RCPrfBase::leaf_count_generic(subtree_height),
        "The tested range and the subtree_height are not compatible");

    // min > max
    EXPECT_THROW(sse::crypto::ConstrainedRCPrfInnerElement<16> elt(
                     sse::crypto::Key<kRCPrfKeySize>(),
                     tree_height,
                     subtree_height,
                     range_max,
                     range_min),
                 std::invalid_argument);

    // subtree height <= 1
    EXPECT_THROW(sse::crypto::ConstrainedRCPrfInnerElement<16> elt(
                     sse::crypto::Key<kRCPrfKeySize>(),
                     tree_height,
                     1,
                     0, // the range and the height hav to be compatible
                     0),
                 std::invalid_argument);

    // subtree height >= tree height
    EXPECT_THROW(sse::crypto::ConstrainedRCPrfInnerElement<16> elt(
                     sse::crypto::Key<kRCPrfKeySize>(),
                     subtree_height,
                     tree_height,
                     range_min,
                     range_max),
                 std::invalid_argument);

    // range and tree height are not matching
    EXPECT_THROW(sse::crypto::ConstrainedRCPrfInnerElement<16> elt(
                     sse::crypto::Key<kRCPrfKeySize>(),
                     tree_height,
                     subtree_height - 1,
                     range_min,
                     range_max),
                 std::invalid_argument);


    // Exceptions raised by the ConstrainedRCPrf constructor
    std::vector<std::unique_ptr<sse::crypto::ConstrainedRCPrfElement<16>>>
        empty_vec;

    EXPECT_THROW(sse::crypto::ConstrainedRCPrf<16> cprf(std::move(empty_vec)),
                 std::invalid_argument);


    std::vector<std::unique_ptr<sse::crypto::ConstrainedRCPrfElement<16>>>
        leaf_vec;
    leaf_vec.emplace_back(new sse::crypto::ConstrainedRCPrfLeafElement<16>(
        std::array<uint8_t, 16>(), tree_height, 0));
    leaf_vec.emplace_back(new sse::crypto::ConstrainedRCPrfLeafElement<16>(
        std::array<uint8_t, 16>(), tree_height, 4));

    EXPECT_THROW(sse::crypto::ConstrainedRCPrf<16> cprf(std::move(leaf_vec)),
                 std::invalid_argument);


    leaf_vec.empty();
    leaf_vec.emplace_back(new sse::crypto::ConstrainedRCPrfLeafElement<16>(
        std::array<uint8_t, 16>(), tree_height, 0));
    leaf_vec.emplace_back(new sse::crypto::ConstrainedRCPrfLeafElement<16>(
        std::array<uint8_t, 16>(), tree_height + 1, 1));
    EXPECT_THROW(sse::crypto::ConstrainedRCPrf<16> cprf(std::move(leaf_vec)),
                 std::invalid_argument);
}