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

#include "tdp_impl/tdp_impl_mbedtls.hpp"
#include "tdp_impl/tdp_impl_openssl.hpp"

#include <sse/crypto/tdp.hpp>
#include <sse/crypto/wrapper.hpp>

#include <iomanip>
#include <iostream>
#include <string>

#include "gtest/gtest.h"

using namespace std;

#define TDP_TEST_COUNT 5 // low test count as we are only testing glue code

// number of test for standard correctness (pk operation first, then sk)
#define TDP_IMPL_CORRECTNESS_TEST_COUNT 30
// number of test for inverted standard correctness (sk operation first, then
// pk)
#define TDP_IMPL_INV_CORRECTNESS_TEST_COUNT 30
#define TDP_IMPL_MULT_EVAL_TEST_COUNT 30

#define TDP_IMPL_MULT_INV_1_TEST_COUNT 30
#define TDP_IMPL_MULT_INV_2_TEST_COUNT 30

#define TDP_IMPL_COPY_TEST_COUNT 30

#define TDP_IMPL_DET_GEN_TEST_COUNT 30

#define POOL_COUNT 20
#define INV_MULT_COUNT 100

// static_if does not exist, so we use a workaround using template
// specialization

template<typename TDP,
         typename TDP_INV,
         typename TDP_POOL,
         bool is_implementation>
class conditional_tdp_test
{
public:
    inline static std::string tdp_eval(const TDP& tdp, const std::string& in)
    {
        return tdp.eval(in);
    }

    inline static std::string tdp_eval(const TDP_INV&     tdp_inv,
                                       const std::string& in)
    {
        return tdp_inv.eval(in);
    }

    inline static std::string tdp_eval(const TDP_POOL&    tdp_mult,
                                       const std::string& in)
    {
        return tdp_mult.eval(in);
    }

    inline static std::string tdp_invert(const TDP_INV&     tdp_inv,
                                         const std::string& in)
    {
        return tdp_inv.invert(in);
    }

    inline static void tdp_eval_pool(const TDP_POOL&    tdp_mult,
                                     const std::string& in,
                                     std::string&       out,
                                     uint8_t            order)
    {
        tdp_mult.eval(in, out, order);
    }

    inline static std::string tdp_eval_pool(const TDP_POOL&    tdp_mult,
                                            const std::string& in,
                                            uint8_t            order)
    {
        return tdp_mult.eval(in, order);
    }

    inline static std::array<uint8_t, sse::crypto::Tdp::kMessageSize>
    tdp_eval_pool(const TDP_POOL& tdp_mult,
                  const std::array<uint8_t, sse::crypto::Tdp::kMessageSize>& in,
                  const uint8_t order)
    {
        return tdp_mult.eval(in, order);
    }

    inline static std::string tdp_invert_mult(const TDP_INV&     tdp_inv,
                                              const std::string& in,
                                              uint8_t            order)
    {
        return tdp_inv.invert_mult(in, order);
    }
};

template<typename TDP, typename TDP_INV, typename TDP_POOL>
class conditional_tdp_test<TDP, TDP_INV, TDP_POOL, true>
{
public:
    inline static std::string tdp_eval(__attribute__((unused)) const TDP& tdp,
                                       __attribute__((unused))
                                       const std::string& in)
    {
        return std::string();
    }

    inline static std::string tdp_eval(__attribute__((unused))
                                       const TDP_INV& tdp_inv,
                                       __attribute__((unused))
                                       const std::string& in)
    {
        return std::string();
    }

    inline static std::string tdp_eval(__attribute__((unused))
                                       const TDP_POOL& tdp_mult,
                                       __attribute__((unused))
                                       const std::string& in)
    {
        return std::string();
    }

    inline static std::string tdp_invert(__attribute__((unused))
                                         const TDP_INV& tdp_inv,
                                         __attribute__((unused))
                                         const std::string& in)
    {
        return std::string();
    }

    inline static void tdp_eval_pool(const TDP_POOL&    tdp_mult,
                                     const std::string& in,
                                     std::string&       out,
                                     uint8_t            order)
    {
        tdp_mult.eval_pool(in, out, order);
    }

    inline static std::string tdp_eval_pool(__attribute__((unused))
                                            const TDP_POOL& tdp_mult,
                                            __attribute__((unused))
                                            const std::string& in,
                                            __attribute__((unused))
                                            uint8_t order)
    {
        return std::string();
    }

    inline static std::array<uint8_t, sse::crypto::Tdp::kMessageSize>
    tdp_eval_pool(const TDP_POOL& tdp_mult,
                  const std::array<uint8_t, sse::crypto::Tdp::kMessageSize>& in,
                  const uint8_t order)
    {
        return tdp_mult.eval_pool(in, order);
    }

    inline static std::string tdp_invert_mult(__attribute__((unused))
                                              const TDP_INV& tdp_inv,
                                              __attribute__((unused))
                                              const std::string& in,
                                              __attribute__((unused))
                                              uint8_t order)
    {
        return std::string();
    }
};


template<typename TDP,
         typename TDP_INV,
         typename TDP_POOL,
         bool is_implementation>
static void test_tdp_impl_correctness(const size_t test_count)
{
    using tdp_test
        = conditional_tdp_test<TDP, TDP_INV, TDP_POOL, is_implementation>;

    for (size_t i = 0; i < test_count; i++) {
        TDP_INV tdp_inv;

        string pk = tdp_inv.public_key();

        TDP      tdp(pk);
        TDP_POOL tdp_mult(pk, 2);


        auto   sample        = tdp.sample_array();
        string sample_string = std::string(sample.begin(), sample.end());

        string enc, enc2;
        tdp.eval(sample_string, enc);


        enc2 = tdp_test::tdp_eval(tdp, sample_string);

        std::array<uint8_t, sse::crypto::Tdp::kMessageSize> enc_arr
            = tdp.eval(sample);
        std::array<uint8_t, sse::crypto::Tdp::kMessageSize> enc_arr_inv
            = tdp_inv.eval(sample);

        string enc_inv;
        tdp_inv.eval(sample_string, enc_inv);

        if (!is_implementation) {
            ASSERT_EQ(enc, enc2);
        }
        ASSERT_EQ(enc, enc_inv);
        ASSERT_EQ(enc, std::string(enc_arr.begin(), enc_arr.end()));
        ASSERT_EQ(enc_arr, enc_arr_inv);


        string enc_mult1, enc_mult2;
        tdp_mult.eval(sample_string, enc_mult1);
        enc_mult2 = tdp_test::tdp_eval(tdp_mult, sample_string);

        if (!is_implementation) {
            ASSERT_EQ(enc_mult1, enc_mult2);
        }
        ASSERT_EQ(enc_mult1, enc);


        string dec;
        tdp_inv.invert(enc, dec);

        ASSERT_EQ(sample_string, dec);


        std::array<uint8_t, sse::crypto::Tdp::kMessageSize> enc_array;
        ::copy(enc.begin(), enc.end(), enc_array.begin());
        std::array<uint8_t, sse::crypto::Tdp::kMessageSize> dec_array
            = tdp_inv.invert(enc_array);

        ASSERT_EQ(sample, dec_array);
    }

    for (size_t i = 0; i < test_count; i++) {
        TDP_INV tdp_inv;

        string pk = tdp_inv.public_key();

        TDP      tdp(pk);
        TDP_POOL tdp_mult(pk, 2);


        string sample_string = tdp.sample();

        string enc, enc2;
        tdp.eval(sample_string, enc);

        enc2 = tdp_test::tdp_eval(tdp, sample_string);

        string enc_inv, enc_inv2;
        tdp_inv.eval(sample_string, enc_inv);
        enc_inv2 = tdp_test::tdp_eval(tdp_inv, sample_string);

        ASSERT_EQ(enc, enc_inv);
        if (!is_implementation) {
            ASSERT_EQ(enc, enc2);
            ASSERT_EQ(enc, enc_inv2);
        }

        string enc_mult1, enc_mult2;
        tdp_mult.eval(sample_string, enc_mult1);
        enc_mult2 = tdp_test::tdp_eval(tdp_mult, sample_string);


        if (!is_implementation) {
            ASSERT_EQ(enc_mult1, enc_mult2);
        }
        ASSERT_EQ(enc_mult1, enc);


        string dec, dec2;
        tdp_inv.invert(enc, dec);
        dec2 = tdp_test::tdp_invert(tdp_inv, enc);

        ASSERT_EQ(sample_string, dec);
        if (!is_implementation) {
            ASSERT_EQ(sample_string, dec2);
        }
    }
}


template<typename TDP,
         typename TDP_INV,
         typename TDP_POOL,
         bool is_implementation>
static void test_tdp_impl_inverse_correctness(const size_t test_count)
{
    for (size_t i = 0; i < test_count; i++) {
        TDP_INV tdp_inv;

        string pk = tdp_inv.public_key();

        TDP tdp(pk);

        auto   sample_arr = tdp_inv.sample_array();
        string sample     = std::string(sample_arr.begin(), sample_arr.end());

        string v = sample;
        string res;

        tdp_inv.invert_mult(v, res, 0);

        ASSERT_EQ(v, res);

        for (size_t j = 0; j < i; j++) {
            tdp_inv.invert(v, v);
        }

        for (size_t j = 0; j < i; j++) {
            tdp.eval(v, v);
        }


        ASSERT_EQ(sample, v);
    }
}

template<typename TDP,
         typename TDP_INV,
         typename TDP_POOL,
         bool is_implementation>
static void test_tdp_impl_multiple_eval(const size_t string_test_count,
                                        const size_t array_test_count)
{
    using tdp_test
        = conditional_tdp_test<TDP, TDP_INV, TDP_POOL, is_implementation>;

    for (size_t i = 0; i < string_test_count; i++) {
        TDP_INV tdp_inv;

        string pk = tdp_inv.public_key();

        TDP_POOL pool(pk, POOL_COUNT);
        TDP      tdp(pk);


        string sample = pool.sample();

        string v1, v2, v3;
        v2 = sample;
        for (uint8_t j = 1; j < pool.maximum_order(); j++) {
            v1 = tdp_test::tdp_eval_pool(pool, sample, j);
            tdp_inv.eval(v2, v2);
            tdp_test::tdp_eval_pool(pool, sample, v3, j);

            if (!is_implementation) {
                ASSERT_EQ(v1, v2);
            }
            ASSERT_EQ(v2, v3);

            if (j == 1) {
                std::string v0;
                pool.eval(sample, v0);
                ASSERT_EQ(v2, v0);
            }
        }
    }

    for (size_t i = 0; i < array_test_count; i++) {
        TDP_INV tdp_inv;

        string pk = tdp_inv.public_key();

        TDP_POOL pool(pk, POOL_COUNT);
        TDP      tdp(pk);


        std::array<uint8_t, sse::crypto::TdpMultPool::kMessageSize> sample_arr
            = pool.sample_array();
        string sample = string(sample_arr.begin(), sample_arr.end());

        string                                                      v1;
        std::array<uint8_t, sse::crypto::TdpMultPool::kMessageSize> v2;
        for (uint8_t j = 1; j < pool.maximum_order(); j++) {
            tdp_test::tdp_eval_pool(pool, sample, v1, j);
            v2 = tdp_test::tdp_eval_pool(pool, sample_arr, j);

            ASSERT_EQ(v1, string(v2.begin(), v2.end()));

            if (j == 1) {
                auto v0 = pool.eval(sample_arr);
                ASSERT_EQ(v2, v0);
            }
        }
    }
}


template<typename TDP,
         typename TDP_INV,
         typename TDP_POOL,
         bool is_implementation>
static void test_tdp_impl_multiple_inverse_1(const size_t test_count)
{
    using tdp_test
        = conditional_tdp_test<TDP, TDP_INV, TDP_POOL, is_implementation>;

    for (size_t i = 0; i < test_count; i++) {
        TDP_INV tdp_inv;

        string pk = tdp_inv.public_key();

        TDP tdp(pk);


        string sample = tdp_inv.sample();
        std::array<uint8_t, sse::crypto::TdpMultPool::kMessageSize> sample_arr;
        ::copy(sample.begin(), sample.end(), sample_arr.begin());

        string goal, v, w;

        tdp_inv.invert_mult(sample, goal, INV_MULT_COUNT);
        w = tdp_test::tdp_invert_mult(tdp_inv, sample, INV_MULT_COUNT);
        auto goal_arr = tdp_inv.invert_mult(sample_arr, INV_MULT_COUNT);

        v = sample;
        for (size_t j = 0; j < INV_MULT_COUNT; j++) {
            tdp_inv.invert(v, v);
        }
        if (!is_implementation) {
            ASSERT_EQ(goal, w);
        }
        ASSERT_EQ(goal, std::string(goal_arr.begin(), goal_arr.end()));
        ASSERT_EQ(goal, v);
    }
}


template<typename TDP,
         typename TDP_INV,
         typename TDP_POOL,
         bool is_implementation>
static void test_tdp_impl_multiple_inverse_2(const size_t test_count)
{
    TDP_INV tdp_inv;

    string pk = tdp_inv.public_key();

    TDP tdp(pk);


    string sample = tdp_inv.sample();
    string v1, v2;

    v2 = sample;
    for (uint32_t j = 0; j < test_count; j++) {
        tdp_inv.invert(v2, v2);
        tdp_inv.invert_mult(sample, v1, j + 1);
        ASSERT_EQ(v1, v2);
    }
}


template<typename TDP,
         typename TDP_INV,
         typename TDP_POOL,
         bool is_implementation>
static void test_tdp_impl_copy(const size_t test_count)
{
    // check that deterministically generated values are consistent after copies

    TDP_INV  temp_inv_tdp;
    TDP      tdp_pk_assign(temp_inv_tdp.public_key());
    TDP_POOL tdp_pool_assign(temp_inv_tdp.public_key(), 3);


    for (size_t i = 0; i < test_count; i++) {
        TDP_INV tdp_inv_orig;
        TDP_INV tdp_inv_sk_copy(tdp_inv_orig.private_key());

        TDP tdp_pk_copy(tdp_inv_orig.public_key());
        TDP tdp_pk_copy_copy = tdp_pk_copy;


        TDP_POOL tdp_pool(tdp_inv_orig.public_key(), 2);
        TDP_POOL tdp_pool_copy(tdp_pool);

        tdp_pk_assign   = tdp_pk_copy_copy;
        tdp_pool_assign = tdp_pool_copy;

        // check that tdp inverse have the same private key
        ASSERT_EQ(tdp_inv_sk_copy.private_key(), tdp_inv_orig.private_key());

        //        if (!is_implementation) {
        //            ASSERT_EQ(tdp_inv_sk_assign.private_key(),
        //            tdp_inv_orig.private_key());
        //        }


        // check that they have the same public key
        ASSERT_EQ(tdp_inv_sk_copy.public_key(), tdp_inv_orig.public_key());
        ASSERT_EQ(tdp_pk_copy.public_key(), tdp_inv_orig.public_key());
        ASSERT_EQ(tdp_pk_copy_copy.public_key(), tdp_inv_orig.public_key());
        if (!is_implementation) {
            //            ASSERT_EQ(tdp_inv_sk_assign.public_key(),
            //            tdp_inv_orig.public_key());
            ASSERT_EQ(tdp_pk_assign.public_key(), tdp_inv_orig.public_key());
        }

        ASSERT_EQ(tdp_pool.public_key(), tdp_inv_orig.public_key());
        ASSERT_EQ(tdp_pool_copy.public_key(), tdp_inv_orig.public_key());
        if (!is_implementation) {
            ASSERT_EQ(tdp_pool_assign.public_key(), tdp_inv_orig.public_key());
        }

        // for the pools, also check that they have the same size
        ASSERT_EQ(tdp_pool_copy.maximum_order(), tdp_pool.maximum_order());
        if (!is_implementation) {
            ASSERT_EQ(tdp_pool_assign.maximum_order(),
                      tdp_pool.maximum_order());
        }

        std::array<uint8_t, 32> key = sse::crypto::random_bytes<uint8_t, 32>();

        for (size_t j = 0; j < 10; j++) {
            std::array<uint8_t, 32> key1 = key;
            std::array<uint8_t, 32> key2 = key;
            std::array<uint8_t, 32> key3 = key;
            //            std::array<uint8_t, 32> key4 = key;
            std::array<uint8_t, 32> key5 = key;
            std::array<uint8_t, 32> key6 = key;
            std::array<uint8_t, 32> key7 = key;

            string sample_orig = tdp_inv_orig.generate(
                sse::crypto::Key<32>(key1.data()), std::to_string(j));
            string sample_orig_copy = tdp_inv_orig.generate(
                sse::crypto::Key<32>(key2.data()), std::to_string(j));
            string sample_sk_copy = tdp_inv_orig.generate(
                sse::crypto::Key<32>(key3.data()), std::to_string(j));
            //            string sample_inv_assign =
            //            tdp_inv_sk_assign.generate(sse::crypto::Key<32>(key4.data()),
            //            std::to_string(j));
            string sample_pk_copy = tdp_pk_copy.generate(
                sse::crypto::Key<32>(key5.data()), std::to_string(j));
            string sample_eq = tdp_pk_copy_copy.generate(
                sse::crypto::Key<32>(key6.data()), std::to_string(j));
            string sample_assign = tdp_pk_assign.generate(
                sse::crypto::Key<32>(key7.data()), std::to_string(j));

            ASSERT_EQ(sample_orig_copy, sample_orig);
            ASSERT_EQ(sample_sk_copy, sample_orig);
            ASSERT_EQ(sample_pk_copy, sample_orig);
            ASSERT_EQ(sample_eq, sample_orig);
            if (!is_implementation) {
                //                ASSERT_EQ(sample_inv_assign, sample_orig);
                ASSERT_EQ(sample_assign, sample_orig);
            }
        }
    }
}

template<typename TDP,
         typename TDP_INV,
         typename TDP_POOL,
         bool is_implementation>
static void test_tdp_impl_deterministic_generation(const size_t test_count)
{
    TDP_INV  inv_tdp;
    TDP      tdp(inv_tdp.public_key());
    TDP_POOL pool_tdp(inv_tdp.public_key(), 2);

    std::array<uint8_t, 32> key     = sse::crypto::random_bytes<uint8_t, 32>();
    std::array<uint8_t, 32> key_prf = key;
    const sse::crypto::Prf<sse::crypto::Tdp::kRSAPrfSize> prf(
        sse::crypto::Key<32>(key_prf.data()));

    for (size_t i = 0; i < test_count; i++) {
        std::string             seed    = sse::crypto::random_string(128);
        std::array<uint8_t, 32> key_tmp = key;


        auto tdp_array_key
            = tdp.generate_array(sse::crypto::Key<32>(key_tmp.data()), seed);
        auto tdp_array_prf = tdp.generate_array(prf, seed);

        key_tmp = key;
        std::string tdp_string_key
            = tdp.generate(sse::crypto::Key<32>(key_tmp.data()), seed);
        std::string tdp_string_prf = tdp.generate(prf, seed);

        ASSERT_EQ(tdp_array_key, tdp_array_prf);
        ASSERT_EQ(tdp_string_key, tdp_string_prf);
        ASSERT_EQ(tdp_string_key,
                  std::string(tdp_array_key.begin(), tdp_array_key.end()));

        key_tmp                = key;
        auto inv_tdp_array_key = inv_tdp.generate_array(
            sse::crypto::Key<32>(key_tmp.data()), seed);
        auto inv_tdp_array_prf = inv_tdp.generate_array(prf, seed);

        key_tmp = key;
        std::string inv_tdp_string_key
            = inv_tdp.generate(sse::crypto::Key<32>(key_tmp.data()), seed);
        std::string inv_tdp_string_prf = inv_tdp.generate(prf, seed);

        ASSERT_EQ(inv_tdp_array_key, inv_tdp_array_prf);
        ASSERT_EQ(inv_tdp_string_key, inv_tdp_string_prf);
        ASSERT_EQ(
            inv_tdp_string_key,
            std::string(inv_tdp_array_key.begin(), inv_tdp_array_key.end()));

        ASSERT_EQ(inv_tdp_array_key, tdp_array_key);

        key_tmp                 = key;
        auto pool_tdp_array_key = pool_tdp.generate_array(
            sse::crypto::Key<32>(key_tmp.data()), seed);
        auto pool_tdp_array_prf = pool_tdp.generate_array(prf, seed);

        key_tmp = key;
        std::string pool_tdp_string_key
            = pool_tdp.generate(sse::crypto::Key<32>(key_tmp.data()), seed);
        std::string pool_tdp_string_prf = pool_tdp.generate(prf, seed);

        ASSERT_EQ(pool_tdp_array_key, pool_tdp_array_prf);
        ASSERT_EQ(pool_tdp_string_key, pool_tdp_string_prf);
        ASSERT_EQ(
            pool_tdp_string_key,
            std::string(pool_tdp_array_key.begin(), pool_tdp_array_key.end()));

        ASSERT_EQ(pool_tdp_array_key, tdp_array_key);
    }
}

template<typename TDP,
         typename TDP_INV,
         typename TDP_POOL,
         bool is_implementation>
static void test_tdp_impl_exceptions()
{
    using tdp_test
        = conditional_tdp_test<TDP, TDP_INV, TDP_POOL, is_implementation>;

    ASSERT_THROW(TDP tdp(" "), std::runtime_error);
    ASSERT_THROW(TDP_INV tdp_inv(" "), std::runtime_error);
    ASSERT_THROW(TDP_POOL pool(" ", 2), std::runtime_error);

    TDP_INV tdp_inv;

    std::string out;

    ASSERT_THROW(tdp_inv.invert(" ", out), std::invalid_argument);

    ASSERT_THROW(TDP_POOL pool(tdp_inv.public_key(), 0), std::invalid_argument);

    TDP_POOL pool(tdp_inv.public_key(), 2);

    ASSERT_THROW(tdp_inv.eval(" ", out), std::invalid_argument);

    ASSERT_THROW(tdp_test::tdp_eval_pool(pool, " ", out, 1),
                 std::invalid_argument);
    ASSERT_THROW(tdp_test::tdp_eval_pool(pool, pool.sample(), out, 45),
                 std::invalid_argument);
}

// Instantiate all the previous test templates
#ifdef WITH_OPENSSL
TEST(tdp_openssl_impl, correctness)
{
    test_tdp_impl_correctness<sse::crypto::TdpImpl_OpenSSL,
                              sse::crypto::TdpInverseImpl_OpenSSL,
                              sse::crypto::TdpMultPoolImpl_OpenSSL,
                              true>(TDP_IMPL_CORRECTNESS_TEST_COUNT);
}
#endif

TEST(tdp_mbedtls_impl, correctness)
{
    test_tdp_impl_correctness<sse::crypto::TdpImpl_mbedTLS,
                              sse::crypto::TdpInverseImpl_mbedTLS,
                              sse::crypto::TdpMultPoolImpl_mbedTLS,
                              true>(TDP_IMPL_CORRECTNESS_TEST_COUNT);
}


TEST(tdp, correctness)
{
    test_tdp_impl_correctness<sse::crypto::Tdp,
                              sse::crypto::TdpInverse,
                              sse::crypto::TdpMultPool,
                              false>(TDP_TEST_COUNT);
}

#ifdef WITH_OPENSSL
TEST(tdp_openssl_impl, inverse_correctness)
{
    test_tdp_impl_inverse_correctness<sse::crypto::TdpImpl_OpenSSL,
                                      sse::crypto::TdpInverseImpl_OpenSSL,
                                      sse::crypto::TdpMultPoolImpl_OpenSSL,
                                      true>(
        TDP_IMPL_INV_CORRECTNESS_TEST_COUNT);
}
#endif

TEST(tdp_mbedtls_impl, inverse_correctness)
{
    test_tdp_impl_inverse_correctness<sse::crypto::TdpImpl_mbedTLS,
                                      sse::crypto::TdpInverseImpl_mbedTLS,
                                      sse::crypto::TdpMultPoolImpl_mbedTLS,
                                      true>(
        TDP_IMPL_INV_CORRECTNESS_TEST_COUNT);
}

TEST(tdp, inverse_correctness)
{
    test_tdp_impl_inverse_correctness<sse::crypto::Tdp,
                                      sse::crypto::TdpInverse,
                                      sse::crypto::TdpMultPool,
                                      false>(TDP_TEST_COUNT);
}


#ifdef WITH_OPENSSL
TEST(tdp_openssl_impl, multiple_eval)
{
    test_tdp_impl_multiple_eval<sse::crypto::TdpImpl_OpenSSL,
                                sse::crypto::TdpInverseImpl_OpenSSL,
                                sse::crypto::TdpMultPoolImpl_OpenSSL,
                                true>(TDP_IMPL_MULT_EVAL_TEST_COUNT / 2,
                                      TDP_IMPL_MULT_EVAL_TEST_COUNT
                                          - TDP_IMPL_MULT_EVAL_TEST_COUNT / 2);
}
#endif

TEST(tdp_mbedtls_impl, multiple_eval)
{
    test_tdp_impl_multiple_eval<sse::crypto::TdpImpl_mbedTLS,
                                sse::crypto::TdpInverseImpl_mbedTLS,
                                sse::crypto::TdpMultPoolImpl_mbedTLS,
                                true>(TDP_IMPL_MULT_EVAL_TEST_COUNT / 2,
                                      TDP_IMPL_MULT_EVAL_TEST_COUNT
                                          - TDP_IMPL_MULT_EVAL_TEST_COUNT / 2);
}

TEST(tdp, multiple_eval)
{
    test_tdp_impl_multiple_eval<sse::crypto::Tdp,
                                sse::crypto::TdpInverse,
                                sse::crypto::TdpMultPool,
                                false>(TDP_TEST_COUNT / 2,
                                       TDP_TEST_COUNT - TDP_TEST_COUNT / 2);
}

#ifdef WITH_OPENSSL
TEST(tdp_openssl_impl, multiple_inverse_1)
{
    test_tdp_impl_multiple_inverse_1<sse::crypto::TdpImpl_OpenSSL,
                                     sse::crypto::TdpInverseImpl_OpenSSL,
                                     sse::crypto::TdpMultPoolImpl_OpenSSL,
                                     true>(TDP_IMPL_MULT_INV_1_TEST_COUNT);
}
#endif

TEST(tdp_mbedtls_impl, multiple_inverse_1)
{
    test_tdp_impl_multiple_inverse_1<sse::crypto::TdpImpl_mbedTLS,
                                     sse::crypto::TdpInverseImpl_mbedTLS,
                                     sse::crypto::TdpMultPoolImpl_mbedTLS,
                                     true>(TDP_IMPL_MULT_INV_1_TEST_COUNT);
}

TEST(tdp, multiple_inverse_1)
{
    test_tdp_impl_multiple_inverse_1<sse::crypto::Tdp,
                                     sse::crypto::TdpInverse,
                                     sse::crypto::TdpMultPool,
                                     false>(TDP_TEST_COUNT);
}

#ifdef WITH_OPENSSL
TEST(tdp_openssl_impl, multiple_inverse_2)
{
    test_tdp_impl_multiple_inverse_2<sse::crypto::TdpImpl_OpenSSL,
                                     sse::crypto::TdpInverseImpl_OpenSSL,
                                     sse::crypto::TdpMultPoolImpl_OpenSSL,
                                     true>(TDP_IMPL_MULT_INV_2_TEST_COUNT);
}
#endif

TEST(tdp_mbedtls_impl, multiple_inverse_2)
{
    test_tdp_impl_multiple_inverse_2<sse::crypto::TdpImpl_mbedTLS,
                                     sse::crypto::TdpInverseImpl_mbedTLS,
                                     sse::crypto::TdpMultPoolImpl_mbedTLS,
                                     true>(TDP_IMPL_MULT_INV_2_TEST_COUNT);
}

TEST(tdp, multiple_inverse_2)
{
    test_tdp_impl_multiple_inverse_2<sse::crypto::Tdp,
                                     sse::crypto::TdpInverse,
                                     sse::crypto::TdpMultPool,
                                     false>(TDP_TEST_COUNT);
}

#ifdef WITH_OPENSSL
TEST(tdp_openssl_impl, copy)
{
    test_tdp_impl_copy<sse::crypto::TdpImpl_OpenSSL,
                       sse::crypto::TdpInverseImpl_OpenSSL,
                       sse::crypto::TdpMultPoolImpl_OpenSSL,
                       true>(TDP_IMPL_MULT_INV_2_TEST_COUNT);
}
#endif

TEST(tdp_mbedtls_impl, copy)
{
    test_tdp_impl_copy<sse::crypto::TdpImpl_mbedTLS,
                       sse::crypto::TdpInverseImpl_mbedTLS,
                       sse::crypto::TdpMultPoolImpl_mbedTLS,
                       true>(TDP_IMPL_MULT_INV_2_TEST_COUNT);
}

TEST(tdp, copy)
{
    test_tdp_impl_copy<sse::crypto::Tdp,
                       sse::crypto::TdpInverse,
                       sse::crypto::TdpMultPool,
                       false>(TDP_TEST_COUNT);
}


#ifdef WITH_OPENSSL
TEST(tdp_openssl_impl, deterministic_generation)
{
    test_tdp_impl_deterministic_generation<sse::crypto::TdpImpl_OpenSSL,
                                           sse::crypto::TdpInverseImpl_OpenSSL,
                                           sse::crypto::TdpMultPoolImpl_OpenSSL,
                                           true>(TDP_IMPL_DET_GEN_TEST_COUNT);
}
#endif

TEST(tdp_mbedtls_impl, deterministic_generation)
{
    test_tdp_impl_deterministic_generation<sse::crypto::TdpImpl_mbedTLS,
                                           sse::crypto::TdpInverseImpl_mbedTLS,
                                           sse::crypto::TdpMultPoolImpl_mbedTLS,
                                           true>(TDP_IMPL_DET_GEN_TEST_COUNT);
}

TEST(tdp, deterministic_generation)
{
    test_tdp_impl_deterministic_generation<sse::crypto::Tdp,
                                           sse::crypto::TdpInverse,
                                           sse::crypto::TdpMultPool,
                                           false>(TDP_IMPL_DET_GEN_TEST_COUNT);
}


#ifdef WITH_OPENSSL
TEST(tdp_openssl_impl, exceptions)
{
    test_tdp_impl_exceptions<sse::crypto::TdpImpl_OpenSSL,
                             sse::crypto::TdpInverseImpl_OpenSSL,
                             sse::crypto::TdpMultPoolImpl_OpenSSL,
                             true>();
}
#endif

TEST(tdp_mbedtls_impl, exceptions)
{
    test_tdp_impl_exceptions<sse::crypto::TdpImpl_mbedTLS,
                             sse::crypto::TdpInverseImpl_mbedTLS,
                             sse::crypto::TdpMultPoolImpl_mbedTLS,
                             true>();
}

TEST(tdp, exceptions)
{
    test_tdp_impl_exceptions<sse::crypto::Tdp,
                             sse::crypto::TdpInverse,
                             sse::crypto::TdpMultPool,
                             false>();
}

TEST(tdp, wrapping)
{
    constexpr size_t kNTest = 10;

    // Create new wrapper
    sse::crypto::Wrapper wrapper(
        (sse::crypto::Key<sse::crypto::Wrapper::kKeySize>()));


    sse::crypto::TdpInverse tdp_inv_base;

    // wrap the object
    auto tdp_rep = wrapper.wrap(tdp_inv_base);

    // unwrap the object
    sse::crypto::TdpInverse unwrapped_tdp_inv
        = wrapper.unwrap<sse::crypto::TdpInverse>(tdp_rep);

    for (size_t i = 0; i < kNTest; i++) {
        auto sample = tdp_inv_base.sample_array();
        auto inv1   = tdp_inv_base.invert(sample);
        auto inv2   = unwrapped_tdp_inv.invert(sample);

        ASSERT_EQ(inv1, inv2);

        auto eval1 = tdp_inv_base.eval(sample);
        auto eval2 = unwrapped_tdp_inv.eval(sample);

        ASSERT_EQ(eval1, eval2);
    }
}
