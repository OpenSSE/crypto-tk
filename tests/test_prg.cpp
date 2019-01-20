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

#include <sse/crypto/prg.hpp>
#include <sse/crypto/random.hpp>
#include <sse/crypto/wrapper.hpp>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>

#include "gtest/gtest.h"

#define TEST_COUNT 100

#ifdef CHECK_TEMPLATE_INSTANTIATION
/* To avoid file duplication in code coverage report */

INSTANTIATE_PRG_TEMPLATE_EXTERN(10)
INSTANTIATE_PRG_TEMPLATE_EXTERN(18)

#endif

constexpr size_t kPrgKeySize = sse::crypto::Prg::kKeySize;

TEST(prg, offset_1)
{
    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::Key<kPrgKeySize> k;
        sse::crypto::Prg              prg(std::move(k));

        std::string out1, out2;

        out1 = prg.derive(32);
        out2 = prg.derive(16, 16);

        ASSERT_TRUE(std::equal(out2.begin(), out2.end(), out1.begin() + 16));
    }
}
TEST(prg, offset_2)
{
    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::Key<kPrgKeySize> k;
        sse::crypto::Prg              prg(std::move(k));

        std::string out1, out2;

        out1 = prg.derive(32);
        out2 = prg.derive(15, 16);

        ASSERT_TRUE(std::equal(out2.begin(), out2.end(), out1.begin() + 15));
    }
}

TEST(prg, offset_3)
{
    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::Key<kPrgKeySize> k;
        sse::crypto::Prg              prg(std::move(k));

        std::string out1, out2, out3, out4;

        out1 = prg.derive(33);
        out2 = prg.derive(17, 16);
        out3 = prg.derive(32);
        out4 = prg.derive(16, 16);

        ASSERT_TRUE(std::equal(out2.begin(), out2.end(), out1.begin() + 17));
        ASSERT_TRUE(std::equal(out3.begin(), out3.end(), out1.begin()));
        ASSERT_TRUE(std::equal(out2.begin(), out2.end() - 1, out4.begin() + 1));
    }
}


TEST(prg, consistency_1)
{
    std::array<uint8_t, kPrgKeySize> k{{0x00}};
    std::array<uint8_t, kPrgKeySize> k_cp{{0x00}};

    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::random_bytes(k);
        k_cp = k;

        sse::crypto::Prg prg(sse::crypto::Key<kPrgKeySize>(k.data()));

        std::string out1, out2;

        out1 = prg.derive(32);
        out2 = sse::crypto::Prg::derive(
            sse::crypto::Key<kPrgKeySize>(k_cp.data()), 16, 16);

        ASSERT_TRUE(std::equal(out2.begin(), out2.end(), out1.begin() + 16));
    }
}

TEST(prg, consistency_2)
{
    std::array<uint8_t, kPrgKeySize> k{{0x00}};
    std::array<uint8_t, kPrgKeySize> k_cp{{0x00}};

    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::random_bytes(k);
        k_cp = k;

        sse::crypto::Prg prg(sse::crypto::Key<kPrgKeySize>(k.data()));

        std::string out1, out2;

        out1 = prg.derive(31);
        out2 = sse::crypto::Prg::derive(
            sse::crypto::Key<kPrgKeySize>(k_cp.data()), 16, 15);

        ASSERT_TRUE(std::equal(out2.begin(), out2.end(), out1.begin() + 16));
    }
}

TEST(prg, consistency_3)
{
    std::array<uint8_t, kPrgKeySize> k{{0x00}};
    std::array<uint8_t, kPrgKeySize> k_cp1{{0x00}}, k_cp2{{0x00}};
    std::array<uint8_t, kPrgKeySize> k_cp3{{0x00}}, k_cp4{{0x00}};
    std::array<uint8_t, kPrgKeySize> k_cp5{{0x00}}, k_cp6{{0x00}};

    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::random_bytes(k);
        k_cp1 = k;
        k_cp2 = k;
        k_cp3 = k;
        k_cp4 = k;
        k_cp5 = k;
        k_cp6 = k;

        sse::crypto::Prg prg(sse::crypto::Key<kPrgKeySize>(k.data()));

        std::string out1, out2, out3, out4, out5, out6;
        std::string out8, out10;

        std::array<uint8_t, 58> out_arr;
        uint8_t                 out_bytes[30];

        out1 = prg.derive(64);
        out2 = sse::crypto::Prg::derive(
            sse::crypto::Key<kPrgKeySize>(k_cp1.data()), 16, 64 - 16);
        sse::crypto::Prg::derive(
            sse::crypto::Key<kPrgKeySize>(k_cp2.data()), 64, out3);
        sse::crypto::Prg::derive(
            sse::crypto::Key<kPrgKeySize>(k_cp3.data()), 64, out4);
        out5 = sse::crypto::Prg::derive(
            sse::crypto::Key<kPrgKeySize>(k_cp4.data()), 64);
        sse::crypto::Prg::derive(
            sse::crypto::Key<kPrgKeySize>(k_cp5.data()), 15, 10, out6);
        sse::crypto::Prg::derive(
            sse::crypto::Key<kPrgKeySize>(k_cp6.data()), 6, 58, out_arr.data());

        prg.derive(18, 46, out8);
        prg.derive(34, 30, out_bytes);

        ASSERT_EQ(out2, std::string(out1.begin() + 16, out1.end()));
        ASSERT_EQ(out1, out3);
        ASSERT_EQ(out1, out4);
        ASSERT_EQ(out1, out5);
        ASSERT_EQ(out6, std::string(out1.begin() + 15, out1.begin() + 15 + 10));
        ASSERT_EQ(std::string(out_arr.begin(), out_arr.end()),
                  std::string(out1.begin() + 6, out1.begin() + 6 + 58));

        ASSERT_EQ(out8, std::string(out1.begin() + 18, out1.end()));
        ASSERT_EQ(std::string(reinterpret_cast<char*>(out_bytes), 30),
                  std::string(out1.begin() + 34, out1.end()));
    }
}

// small workaround to declare the content of this function as a friend
// of the Key class, and access its content without having to import gtest
// in the key.hpp header

namespace tests {
template<size_t K_SIZE>
void prg_test_key_derivation_consistency();

template<size_t K_SIZE>
void prg_test_key_derivation_consistency()
{
    std::array<uint8_t, kPrgKeySize> k{{0x00}};
    std::array<uint8_t, kPrgKeySize> k_cp1{{0x00}}, k_cp2{{0x00}};
    std::array<uint8_t, kPrgKeySize> k_cp3{{0x00}}, k_cp4{{0x00}};
    std::array<uint8_t, kPrgKeySize> k_loc;

    // check that calls to derive_keys with 0 as input returns empty vectors
    {
        sse::crypto::Key<kPrgKeySize> key, k1, k2;
        sse::crypto::Prg              prg(std::move(key));

        ASSERT_EQ(prg.derive_keys<16>(0, 0).size(), 0);
        ASSERT_EQ(prg.derive_keys<32>(0).size(), 0);
        ASSERT_EQ(sse::crypto::Prg::derive_keys<16>(std::move(k1), 0, 0).size(),
                  0);
        ASSERT_EQ(sse::crypto::Prg::derive_keys<32>(std::move(k2), 0).size(),
                  0);
    }

    constexpr size_t n_derived_keys_max = TEST_COUNT + 1;
    static_assert(n_derived_keys_max <= UINT16_MAX,
                  "The number of derived keys is too large");


    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::random_bytes(k);
        k_cp1 = k;
        k_cp2 = k;
        k_cp3 = k;
        k_cp4 = k;

        constexpr size_t   derived_key_size = K_SIZE;
        uint16_t           n_derived_keys   = static_cast<uint16_t>(i + 1);
        constexpr uint16_t key_offset       = 3;

        std::array<uint8_t,
                   (n_derived_keys_max + key_offset) * derived_key_size>
            out;


        auto key_vec_static = sse::crypto::Prg::derive_keys<derived_key_size>(
            sse::crypto::Key<kPrgKeySize>(k.data()), n_derived_keys);
        auto offet_key_vec_static
            = sse::crypto::Prg::derive_keys<derived_key_size>(
                sse::crypto::Key<kPrgKeySize>(k_cp1.data()),
                n_derived_keys,
                key_offset);

        sse::crypto::Prg prg(sse::crypto::Key<kPrgKeySize>(k_cp3.data()));
        auto key_vec = prg.derive_keys<derived_key_size>(n_derived_keys);
        auto offet_key_vec
            = prg.derive_keys<derived_key_size>(n_derived_keys, key_offset);


        // check that the number of derived keys is OK
        ASSERT_EQ(key_vec_static.size(), n_derived_keys);
        ASSERT_EQ(offet_key_vec_static.size(), n_derived_keys);
        ASSERT_EQ(key_vec.size(), n_derived_keys);
        ASSERT_EQ(offet_key_vec.size(), n_derived_keys);

        sse::crypto::Prg::derive(
            sse::crypto::Key<kPrgKeySize>(k_cp2.data()), 0, out);

        for (uint16_t j = 0; j < n_derived_keys; j++) {
            k_loc = k_cp4;

            key_vec[j].unlock();
            key_vec_static[j].unlock();
            ASSERT_TRUE(memcmp(key_vec[j].data(),
                               out.data() + j * derived_key_size,
                               derived_key_size)
                        == 0);
            ASSERT_TRUE(memcmp(key_vec_static[j].data(),
                               out.data() + j * derived_key_size,
                               derived_key_size)
                        == 0);
            ASSERT_TRUE(memcmp(key_vec_static[j].data(),
                               prg.derive_key<derived_key_size>(j).unlock_get(),
                               derived_key_size)
                        == 0);
            ASSERT_TRUE(
                memcmp(key_vec_static[j].data(),
                       sse::crypto::Prg::derive_key<derived_key_size>(
                           sse::crypto::Key<kPrgKeySize>(k_loc.data()), j)
                           .unlock_get(),
                       derived_key_size)
                == 0);
            key_vec[j].lock();
            key_vec_static[j].lock();
        }
        for (size_t j = 0; j < n_derived_keys; j++) {
            offet_key_vec_static[j].unlock();
            offet_key_vec[j].unlock();
            ASSERT_TRUE(memcmp(offet_key_vec_static[j].data(),
                               out.data() + (j + key_offset) * derived_key_size,
                               derived_key_size)
                        == 0);
            ASSERT_TRUE(memcmp(offet_key_vec[j].data(),
                               out.data() + (j + key_offset) * derived_key_size,
                               derived_key_size)
                        == 0);
            offet_key_vec_static[j].lock();
            offet_key_vec[j].lock();
        }
    }
}
} // namespace tests

TEST(prg, consistency_4)
{
    tests::prg_test_key_derivation_consistency<16>();
    tests::prg_test_key_derivation_consistency<18>();
    tests::prg_test_key_derivation_consistency<32>();
}

TEST(prg, wrapping)
{
    constexpr size_t kLenTest = 1000;
    // Create new wrapper
    sse::crypto::Wrapper wrapper(
        (sse::crypto::Key<sse::crypto::Wrapper::kKeySize>()));

    // Create a Prg object
    sse::crypto::Prg base_prg((sse::crypto::Key<kPrgKeySize>()));


    // wrap the object
    auto prg_rep = wrapper.wrap(base_prg);

    // unwrap the object
    sse::crypto::Prg unwrapped_prg = wrapper.unwrap<sse::crypto::Prg>(prg_rep);

    std::string out1, out2;

    out1 = base_prg.derive(kLenTest);
    out2 = unwrapped_prg.derive(kLenTest);

    ASSERT_EQ(out1, out2);
}

TEST(prg, exceptions)
{
    std::array<uint8_t, kPrgKeySize> k{{0x00}};
    sse::crypto::Key<kPrgKeySize>    key;
    sse::crypto::Prg prg(sse::crypto::Key<kPrgKeySize>(k.data()));

    std::string out;

    ASSERT_THROW(prg.derive(0, 10, NULL), std::invalid_argument);

    sse::crypto::Prg::derive(std::move(key), 1, out);
    // key should have been emptied by the previous line
    ASSERT_THROW(sse::crypto::Prg::derive(std::move(key), 10, out),
                 std::invalid_argument);
    ASSERT_THROW(sse::crypto::Prg::derive_keys<10>(std::move(key), 10),
                 std::invalid_argument);

    ASSERT_THROW(sse::crypto::Prg p(sse::crypto::Key<kPrgKeySize>(NULL)),
                 std::invalid_argument);
}
