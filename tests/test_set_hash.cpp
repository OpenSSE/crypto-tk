//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2017 Jeremy Maitin-Shepard, Raphael Bost
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

#include <sse/crypto/hash.hpp>
#include <sse/crypto/random.hpp>
#include <sse/crypto/set_hash.hpp>

#include <iostream>
#include <vector>

#include "gtest/gtest.h"

// Size in bytes of the elements hashed
constexpr size_t kNumTests     = 20;
constexpr size_t kTestEltsSize = 100;
constexpr size_t kNumEltsBatch = 20;

using sse::crypto::SetHash;


TEST(set_hash, constructors)
{
    for (size_t i = 0; i < kNumTests; i++) {
        SetHash a;

        // generate random elements
        std::string e_1 = sse::crypto::random_string(kTestEltsSize);
        std::string e_2 = sse::crypto::random_string(kTestEltsSize);

        SetHash b(a), c, d, e(a.data());
        c = a;
        d = a;

        SetHash f(std::move(d));
        ASSERT_EQ(a, b);
        ASSERT_EQ(a, c);
        ASSERT_EQ(a, e);
        ASSERT_EQ(a, f);
    }
}

TEST(set_hash, commutativity)
{
    for (size_t i = 0; i < kNumTests; i++) {
        SetHash a, b, c, d;

        ASSERT_EQ(a, b);
        ASSERT_EQ(a, c);
        ASSERT_EQ(a, d);

        // generate random elements
        std::string e_1 = sse::crypto::random_string(kTestEltsSize);
        std::string e_2 = sse::crypto::random_string(kTestEltsSize);

        // add them in two different orders
        a.add_element(e_1);
        a.add_element(e_2);

        b.add_element(e_2);
        b.add_element(e_1);

        ASSERT_EQ(a, b);

        // remove them in two different orders
        c.add_element(e_1);
        c.add_element(e_2);

        d.add_element(e_2);
        d.add_element(e_1);

        ASSERT_EQ(c, d);
    }
}


TEST(set_hash, associativity_insert)
{
    for (size_t i = 0; i < kNumTests; i++) {
        SetHash a, b, c, d;

        ASSERT_EQ(a, b);
        ASSERT_EQ(a, c);
        ASSERT_EQ(a, d);

        std::string e_1 = sse::crypto::random_string(kTestEltsSize);
        std::string e_2 = sse::crypto::random_string(kTestEltsSize);
        std::string e_3 = sse::crypto::random_string(kTestEltsSize);

        a.add_element(e_1);
        a.add_element(e_2);
        b.add_element(e_3);

        a.add_set(b);

        c.add_element(e_1);

        d.add_element(e_2);
        d.add_element(e_3);

        c.add_set(d);

        ASSERT_EQ(a, c);
    }
}

TEST(set_hash, associativity_remove)
{
    for (size_t i = 0; i < kNumTests; i++) {
        SetHash a, b, c, d, I;

        ASSERT_EQ(a, b);
        ASSERT_EQ(a, c);

        std::string e_1 = sse::crypto::random_string(kTestEltsSize);
        std::string e_2 = sse::crypto::random_string(kTestEltsSize);

        a.add_element(e_1);
        a.add_element(e_2);

        b = a;
        c = a;
        d = a;

        b.remove_element(e_1);
        b.remove_element(e_2);

        c.remove_element(e_2);
        c.remove_element(e_1);

        a.remove_set(d);

        ASSERT_EQ(b, c);
        ASSERT_EQ(b, a);
        ASSERT_FALSE(b != I); // to test the != operator
    }
}

TEST(set_hash, identity)
{
    // an empty set should be represented by the infinite point
    SetHash empty;
    EXPECT_EQ(empty.data(), SetHash::kECInfinitePoint);

    for (size_t i = 0; i < kNumTests; i++) {
        SetHash a, b, c, I;
        ASSERT_EQ(a, b);
        ASSERT_EQ(a, c);
        ASSERT_EQ(a, I);

        std::string e_1 = sse::crypto::random_string(kTestEltsSize);
        std::string e_2 = sse::crypto::random_string(kTestEltsSize);

        a.add_element(e_1);
        a.add_element(e_2);

        b = a;
        b.add_set(I);

        c = a;
        c.remove_set(I);

        ASSERT_EQ(a, b);
        ASSERT_EQ(a, c);

        a.remove_set(c);
        ASSERT_EQ(a, I);
    }
}

TEST(set_hash, batch_constructor)
{
    for (size_t i = 0; i < kNumTests; i++) {
        std::vector<std::string> samples(kNumEltsBatch);
        SetHash                  a;
        for (auto& e : samples) {
            e = sse::crypto::random_string(kTestEltsSize);
            a.add_element(e);
        }

        SetHash b(samples);

        ASSERT_EQ(a, b);
    }
}

TEST(set_hash, exception)
{
    std::array<uint8_t, SetHash::kSetHashSize> in{
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};

    ASSERT_THROW(SetHash a(in), std::invalid_argument);
}
