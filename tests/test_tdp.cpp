//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2016 Raphael Bost
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

#include "../src/tdp.hpp"

#include <iostream>
#include <iomanip>
#include <string>

#include "gtest/gtest.h"

using namespace std;

#define TEST_COUNT 30
#define POOL_COUNT 20
#define INV_MULT_COUNT 100

TEST(tdp, correctness)
{
    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::TdpInverse tdp_inv;
        
        string pk = tdp_inv.public_key();
        
        sse::crypto::Tdp tdp(pk);
        sse::crypto::TdpMultPool tdp_mult(pk, 2);

        
        auto sample = tdp.sample_array();
        string sample_string = std::string(sample.begin(), sample.end());
        
        string enc = tdp.eval(sample_string);
        string enc2;
        tdp.eval(sample_string, enc2);

        std::array<uint8_t, sse::crypto::Tdp::kMessageSize> enc_arr = tdp.eval(sample);
        std::array<uint8_t, sse::crypto::Tdp::kMessageSize> enc_arr_inv = tdp_inv.eval(sample);
        
        string enc_inv;
        tdp_inv.eval(sample_string, enc_inv);
        
        ASSERT_EQ(enc, enc2);
        ASSERT_EQ(enc, enc_inv);
        ASSERT_EQ(enc, std::string(enc_arr.begin(), enc_arr.end()));
        ASSERT_EQ(enc_arr, enc_arr_inv);

        
        string enc_mult1 = tdp_mult.eval(sample_string);
        string enc_mult2;
        tdp_mult.eval(sample_string, enc_mult2);
        ASSERT_EQ(enc_mult1, enc_mult2);
        ASSERT_EQ(enc_mult1, enc);

        
        
        string dec = tdp_inv.invert(enc);
        
        ASSERT_EQ(sample_string, dec);
        
        
        std::array<uint8_t, sse::crypto::Tdp::kMessageSize> enc_array;
        ::copy(enc.begin(), enc.end(), enc_array.begin());
        std::array<uint8_t, sse::crypto::Tdp::kMessageSize> dec_array = tdp_inv.invert(enc_array);

        ASSERT_EQ(sample, dec_array);
    }

    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::TdpInverse tdp_inv;
        
        string pk = tdp_inv.public_key();
        
        sse::crypto::Tdp tdp(pk);
        sse::crypto::TdpMultPool tdp_mult(pk, 2);
        
        
        string sample_string = tdp.sample();
        
        string enc = tdp.eval(sample_string);
        string enc2;
        tdp.eval(sample_string, enc2);
        
        string enc_inv;
        tdp_inv.eval(sample_string, enc_inv);
        
        ASSERT_EQ(enc, enc2);
        ASSERT_EQ(enc, enc_inv);
        
        string enc_mult1 = tdp_mult.eval(sample_string);
        string enc_mult2;
        tdp_mult.eval(sample_string, enc_mult2);
        ASSERT_EQ(enc_mult1, enc_mult2);
        ASSERT_EQ(enc_mult1, enc);
        
        
        
        string dec = tdp_inv.invert(enc);
        
        ASSERT_EQ(sample_string, dec);        
    }

}

TEST(tdp, inverse_correctness)
{
    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::TdpInverse tdp_inv;
        
        string pk = tdp_inv.public_key();
        
        sse::crypto::Tdp tdp(pk);
        
        auto sample_arr =  tdp_inv.sample_array();
        string sample = std::string(sample_arr.begin(), sample_arr.end());
        
        string v = sample;
        
        ASSERT_EQ(v, tdp_inv.invert_mult(v,0));
        
        for (size_t j = 0; j < i; j++) {
            v = tdp_inv.invert(v);
        }
        
        for (size_t j = 0; j < i; j++) {
            v = tdp.eval(v);
        }
        
        
        ASSERT_EQ(sample, v);
    }
}


TEST(tdp, multiple_eval)
{
    for (size_t i = 0; i < 2*TEST_COUNT/3; i++) {
        sse::crypto::TdpInverse tdp_inv;
        
        string pk = tdp_inv.public_key();
        
        sse::crypto::TdpMultPool pool(pk, POOL_COUNT);
        sse::crypto::Tdp tdp(pk);
        
        
        string sample = pool.sample();

        string v1, v2, v3;
        v2 = sample;
        for (size_t j = 1; j < pool.maximum_order(); j++) {
            v1 = pool.eval(sample, j);
            v2 = tdp_inv.eval(v2);
            pool.eval(sample, v3, j);
            
            ASSERT_EQ(v1, v2);
            ASSERT_EQ(v1, v3);
            
            if (j == 1) {
                std::string v0 = pool.eval(sample);
                ASSERT_EQ(v1, v0);
            }
        }
        
    }

    for (size_t i = 0; i < (TEST_COUNT-2*TEST_COUNT/3); i++) {
        sse::crypto::TdpInverse tdp_inv;
        
        string pk = tdp_inv.public_key();
        
        sse::crypto::TdpMultPool pool(pk, POOL_COUNT);
        sse::crypto::Tdp tdp(pk);
        
        
        std::array<uint8_t, sse::crypto::TdpMultPool::kMessageSize> sample_arr = pool.sample_array();
        string sample = string(sample_arr.begin(), sample_arr.end());
        
        string v1;
        std::array<uint8_t, sse::crypto::TdpMultPool::kMessageSize> v2;
        for (size_t j = 1; j < pool.maximum_order(); j++) {
            
            v1 = pool.eval(sample,j);
            v2 = pool.eval(sample_arr, j);
            
            ASSERT_EQ(v1, string(v2.begin(), v2.end()));
            
            if (j == 1) {
                auto v0 = pool.eval(sample_arr);
                ASSERT_EQ(v2, v0);
            }
        }
        
    }
}

TEST(tdp, multiple_inverse_1)
{
    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::TdpInverse tdp_inv;
        
        string pk = tdp_inv.public_key();
        
        sse::crypto::Tdp tdp(pk);
        
        
        string sample = tdp_inv.sample();
        std::array<uint8_t, sse::crypto::TdpMultPool::kMessageSize> sample_arr;
        ::copy(sample.begin(), sample.end(), sample_arr.begin());

        string goal, v, w;
        
        goal = tdp_inv.invert_mult(sample, INV_MULT_COUNT);
        tdp_inv.invert_mult(sample, w, INV_MULT_COUNT);
        auto goal_arr = tdp_inv.invert_mult(sample_arr, INV_MULT_COUNT);
        
        v = sample;
        for (size_t j = 0; j < INV_MULT_COUNT; j++) {
            v = tdp_inv.invert(v);
        }
        ASSERT_EQ(goal, v);
        ASSERT_EQ(goal, w);
        ASSERT_EQ(goal, std::string(goal_arr.begin(), goal_arr.end()));
    }
}

TEST(tdp, multiple_inverse_2)
{
        sse::crypto::TdpInverse tdp_inv;
        
        string pk = tdp_inv.public_key();
        
        sse::crypto::Tdp tdp(pk);
        
        
        string sample = tdp_inv.sample();
        string v1, v2;
    
        v2 = sample;
        for (uint32_t j = 0; j < INV_MULT_COUNT; j++) {
            v2 = tdp_inv.invert(v2);
            v1 = tdp_inv.invert_mult(sample, j+1);
            ASSERT_EQ(v1, v2);
        }
    
}

TEST(tdp, copy)
{
    // check that deterministically generated values are consistent after copies
    
    sse::crypto::TdpInverse temp_inv_tdp;
    sse::crypto::TdpInverse tdp_inv_assign(temp_inv_tdp.private_key());
    sse::crypto::Tdp tdp_assign(temp_inv_tdp.public_key());
    sse::crypto::TdpMultPool tdp_pool_assign(temp_inv_tdp.public_key(),2);

    
    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::TdpInverse tdp_inv_orig;
        sse::crypto::TdpInverse tdp_inv_copy(tdp_inv_orig);
        sse::crypto::TdpInverse tdp_inv_sk_copy(tdp_inv_orig.private_key());
        
        sse::crypto::Tdp tdp_pk_copy(tdp_inv_orig.public_key());
        sse::crypto::Tdp tdp_pk_copy_copy = tdp_pk_copy;

        
        sse::crypto::TdpMultPool tdp_pool(tdp_inv_orig.public_key(),2);
        sse::crypto::TdpMultPool tdp_pool_copy(tdp_pool);
        
        
        tdp_inv_assign = tdp_inv_copy;
        tdp_assign = tdp_pk_copy_copy;
        tdp_pool_assign = tdp_pool_copy;

        // check that tdp inverse have the same private key
        ASSERT_EQ(tdp_inv_copy.private_key(), tdp_inv_orig.private_key());
        ASSERT_EQ(tdp_inv_sk_copy.private_key(), tdp_inv_orig.private_key());
        ASSERT_EQ(tdp_inv_assign.private_key(), tdp_inv_orig.private_key());

        
        // check that they have the same public key
        ASSERT_EQ(tdp_inv_copy.public_key(), tdp_inv_orig.public_key());
        ASSERT_EQ(tdp_inv_sk_copy.public_key(), tdp_inv_orig.public_key());
        ASSERT_EQ(tdp_inv_assign.public_key(), tdp_inv_orig.public_key());
        ASSERT_EQ(tdp_pk_copy.public_key(), tdp_inv_orig.public_key());
        ASSERT_EQ(tdp_pk_copy_copy.public_key(), tdp_inv_orig.public_key());
        ASSERT_EQ(tdp_assign.public_key(), tdp_inv_orig.public_key());

        ASSERT_EQ(tdp_pool.public_key(), tdp_inv_orig.public_key());
        ASSERT_EQ(tdp_pool_copy.public_key(), tdp_inv_orig.public_key());
        ASSERT_EQ(tdp_pool_assign.public_key(), tdp_inv_orig.public_key());
        
        
        // for the pools, also check that they have the same size
        ASSERT_EQ(tdp_pool_copy.pool_size(), tdp_pool.pool_size());
        ASSERT_EQ(tdp_pool_assign.pool_size(), tdp_pool.pool_size());
      
        
        std::string key = sse::crypto::random_string(16);
        
        for (size_t j = 0; j < 10; j++) {
            string sample_orig = tdp_inv_orig.generate(key, std::to_string(j));
            string sample_orig_copy = tdp_inv_orig.generate(key, std::to_string(j));
            string sample_sk_copy = tdp_inv_orig.generate(key, std::to_string(j));
            string sample_inv_assign = tdp_inv_assign.generate(key, std::to_string(j));
            string sample_pk_copy = tdp_pk_copy.generate(key, std::to_string(j));
            string sample_eq = tdp_pk_copy_copy.generate(key, std::to_string(j));
            string sample_assign = tdp_assign.generate(key, std::to_string(j));

            ASSERT_EQ(sample_orig_copy, sample_orig);
            ASSERT_EQ(sample_sk_copy, sample_orig);
            ASSERT_EQ(sample_inv_assign, sample_orig);
            ASSERT_EQ(sample_pk_copy, sample_orig);
            ASSERT_EQ(sample_eq, sample_orig);
            ASSERT_EQ(sample_assign, sample_orig);
        }
    }
}


TEST(tdp, deterministic_generation)
{
    sse::crypto::TdpInverse inv_tdp;
    sse::crypto::Tdp tdp(inv_tdp.public_key());
    sse::crypto::TdpMultPool pool_tdp(inv_tdp.public_key(),2);

    std::string key = sse::crypto::random_string(128);
    const sse::crypto::Prf<sse::crypto::Tdp::kRSAPrgSize> prf(key);
    
    for (size_t i = 0; i < TEST_COUNT; i++) {
        std::string seed = sse::crypto::random_string(128);

        auto tdp_array_key = tdp.generate_array(key, seed);
        auto tdp_array_prf = tdp.generate_array(prf, seed);
        std::string tdp_string_key = tdp.generate(key, seed);
        std::string tdp_string_prf = tdp.generate(prf, seed);
        
        ASSERT_EQ(tdp_array_key, tdp_array_prf);
        ASSERT_EQ(tdp_string_key, tdp_string_prf);
        ASSERT_EQ(tdp_string_key, std::string(tdp_array_key.begin(), tdp_array_key.end()));
     
        auto inv_tdp_array_key = inv_tdp.generate_array(key, seed);
        auto inv_tdp_array_prf = inv_tdp.generate_array(prf, seed);
        std::string inv_tdp_string_key = inv_tdp.generate(key, seed);
        std::string inv_tdp_string_prf = inv_tdp.generate(prf, seed);
        
        ASSERT_EQ(inv_tdp_array_key, inv_tdp_array_prf);
        ASSERT_EQ(inv_tdp_string_key, inv_tdp_string_prf);
        ASSERT_EQ(inv_tdp_string_key, std::string(inv_tdp_array_key.begin(), inv_tdp_array_key.end()));
        
        ASSERT_EQ(inv_tdp_array_key, tdp_array_key);
        
        auto pool_tdp_array_key = pool_tdp.generate_array(key, seed);
        auto pool_tdp_array_prf = pool_tdp.generate_array(prf, seed);
        std::string pool_tdp_string_key = pool_tdp.generate(key, seed);
        std::string pool_tdp_string_prf = pool_tdp.generate(prf, seed);
        
        ASSERT_EQ(pool_tdp_array_key, pool_tdp_array_prf);
        ASSERT_EQ(pool_tdp_string_key, pool_tdp_string_prf);
        ASSERT_EQ(pool_tdp_string_key, std::string(pool_tdp_array_key.begin(), pool_tdp_array_key.end()));
        
        ASSERT_EQ(pool_tdp_array_key, tdp_array_key);
        
        
    }
}

TEST(tdp, exceptions)
{
    
    ASSERT_THROW(sse::crypto::Tdp tdp(" "), std::runtime_error);
    ASSERT_THROW(sse::crypto::TdpInverse tdp_inv(" "), std::runtime_error);
    ASSERT_THROW(sse::crypto::TdpMultPool pool(" ",2), std::runtime_error);
    
    sse::crypto::TdpInverse tdp_inv;
    
    std::string out;
    
    ASSERT_THROW(tdp_inv.invert(" ", out), std::invalid_argument);

    ASSERT_THROW(sse::crypto::TdpMultPool pool(tdp_inv.public_key(), 0), std::invalid_argument);
    
    sse::crypto::TdpMultPool pool(tdp_inv.public_key(), 2);
    
    ASSERT_THROW(tdp_inv.eval(" ", out), std::invalid_argument);
    
    ASSERT_THROW(pool.eval(" ", out, 1), std::invalid_argument);
    ASSERT_THROW(pool.eval(pool.sample(), out, 45), std::invalid_argument);

}
