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

#include <opensse/crypto/hash.hpp>
#include <opensse/crypto/prf.hpp>
#include <opensse/crypto/random.hpp>

#include <iomanip>
#include <iostream>
#include <string>

#include "gtest/gtest.h"

using namespace std;
namespace tests {

template<size_t N>
void test_prf_consistency(size_t input_size)
{
    sse::crypto::Prf<N> prf;

    string in_s  = sse::crypto::random_string(input_size);
    auto   out_s = prf.prf(in_s);
    auto   out_buf
        = prf.prf(reinterpret_cast<const uint8_t*>(in_s.data()), input_size);


    ASSERT_EQ(out_s, out_buf);
}

template<size_t N, size_t L>
void test_prf_consistency_array()
{
    sse::crypto::Prf<N> prf;

    std::array<uint8_t, L> in_arr;
    sse::crypto::random_bytes(in_arr);

    auto out_buf = prf.prf(reinterpret_cast<const uint8_t*>(in_arr.data()), L);
    auto out_arr = prf.prf(in_arr);


    ASSERT_EQ(out_arr, out_buf);
}

template<size_t N>
void test_key_derivation_consistency(size_t input_size)
{
    sse::crypto::Prf<N> prf;

    string in_s = sse::crypto::random_string(input_size);

    auto out_array   = prf.prf(in_s);
    auto out_key_s   = prf.derive_key(in_s);
    auto out_key_buf = prf.derive_key(
        reinterpret_cast<const uint8_t*>(in_s.data()), input_size);

    out_key_s.unlock();
    ASSERT_NE(out_key_s.data(), nullptr);
    if (out_key_s.data() != nullptr) {
        ASSERT_TRUE(memcmp(out_array.data(), out_key_s.data(), N) == 0);
    }
    out_key_s.lock();

    out_key_buf.unlock();
    ASSERT_NE(out_key_buf.data(), nullptr);
    if (out_key_buf.data() != nullptr) {
        ASSERT_TRUE(memcmp(out_array.data(), out_key_buf.data(), N) == 0);
    }
    out_key_buf.lock();
}

template<size_t N, size_t L>
void test_key_derivation_consistency_array()
{
    sse::crypto::Prf<N> prf;

    std::array<uint8_t, L> in_arr;
    sse::crypto::random_bytes(in_arr);

    auto out_array = prf.prf(in_arr);
    auto out_key   = prf.derive_key(in_arr);
    out_key.unlock();
    ASSERT_NE(out_key.data(), nullptr);
    if (out_key.data() != nullptr) {
        ASSERT_TRUE(memcmp(out_array.data(), out_key.data(), N) == 0);
    }
    out_key.lock();
}

} // namespace tests

TEST(prf, consistency)
{
    for (size_t i = 1; i <= 2 * sse::crypto::Hash::kDigestSize + 20; i++) {
        tests::test_prf_consistency<1>(i);
        tests::test_prf_consistency<10>(i);
        tests::test_prf_consistency<20>(i);
        tests::test_prf_consistency<128>(i);
        tests::test_prf_consistency<1024>(i);
        tests::test_prf_consistency<2000>(i);
    }
    tests::test_prf_consistency_array<1, 20>();
    tests::test_prf_consistency_array<10, 40>();
    tests::test_prf_consistency_array<20, 50>();
    tests::test_prf_consistency_array<128, 100>();
    tests::test_prf_consistency_array<1024, 200>();
}

TEST(prf, key_derivation_consistency)
{
    for (size_t i = 1; i <= 2 * sse::crypto::Hash::kDigestSize + 20; i++) {
        tests::test_key_derivation_consistency<1>(i);
        tests::test_key_derivation_consistency<10>(i);
        tests::test_key_derivation_consistency<20>(i);
        tests::test_key_derivation_consistency<128>(i);
        tests::test_key_derivation_consistency<1024>(i);
        tests::test_key_derivation_consistency<2000>(i);
    }

    tests::test_key_derivation_consistency_array<1, 20>();
    tests::test_key_derivation_consistency_array<10, 40>();
    tests::test_key_derivation_consistency_array<20, 50>();
    tests::test_key_derivation_consistency_array<128, 100>();
    tests::test_key_derivation_consistency_array<1024, 200>();
}

TEST(prf, exceptions)
{
    sse::crypto::Prf<20> prf;

    ASSERT_THROW(prf.prf(nullptr, 0), std::invalid_argument);
}
