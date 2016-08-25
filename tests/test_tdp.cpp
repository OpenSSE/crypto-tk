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

#include "../tests/test_tdp.hpp"

#include "../src/tdp.hpp"

#include <iostream>
#include <iomanip>
#include <string>

#include "boost_test_include.hpp"

using namespace std;

#define TEST_COUNT 10
#define POOL_COUNT 20
#define INV_MULT_COUNT 1000

void tdp_correctness_test()
{
    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::TdpInverse tdp_inv;
        
        string pk = tdp_inv.public_key();
        
        sse::crypto::Tdp tdp(pk);

        
        string sample = tdp.sample();
        
        string enc = tdp.eval(sample);
        
        string dec = tdp_inv.invert(enc);
        
        BOOST_CHECK(sample == dec);
    }
}

void tdp_functional_test()
{
    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::TdpInverse tdp_inv;
        
        string pk = tdp_inv.public_key();
        
        sse::crypto::Tdp tdp(pk);
        
        
        string sample = tdp_inv.sample();
        
        string v = sample;
        for (size_t j = 0; j < i; j++) {
            v = tdp_inv.invert(v);
        }
        
        for (size_t j = 0; j < i; j++) {
            v = tdp.eval(v);
        }
        
        
        BOOST_CHECK(sample == v);
    }
}


void tdp_mult_eval_test()
{
    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::TdpInverse tdp_inv;
        
        string pk = tdp_inv.public_key();
        
        sse::crypto::TdpMultPool pool(pk, POOL_COUNT);
        sse::crypto::Tdp tdp(pk);
        
        
        string sample = pool.sample();
        string v1, v2;
        v2 = sample;
        for (size_t j = 1; j < pool.maximum_order(); j++) {
            v1 = pool.eval(sample, j);
            v2 = tdp_inv.eval(v2);

            BOOST_CHECK(v1 == v2);
        }
        
    }
}

void tdp_mult_inv_test()
{
    for (size_t i = 0; i < TEST_COUNT; i++) {
        sse::crypto::TdpInverse tdp_inv;
        
        string pk = tdp_inv.public_key();
        
        sse::crypto::Tdp tdp(pk);
        
        
        string sample = tdp_inv.sample();
        string goal, v;
        
        goal = tdp_inv.invert_mult(sample, INV_MULT_COUNT);
        
        v = sample;
        for (size_t j = 0; j < INV_MULT_COUNT; j++) {
            v = tdp_inv.invert(v);
        }
        BOOST_CHECK(goal == v);
        
    }
}

void tdp_full_mult_inv_test()
{
        sse::crypto::TdpInverse tdp_inv;
        
        string pk = tdp_inv.public_key();
        
        sse::crypto::Tdp tdp(pk);
        
        
        string sample = tdp_inv.sample();
        string v1, v2;
        
//        goal = tdp_inv.invert_mult(sample, INV_MULT_COUNT);
    
        v2 = sample;
        for (uint32_t j = 0; j < INV_MULT_COUNT; j++) {
            v2 = tdp_inv.invert(v2);
            v1 = tdp_inv.invert_mult(sample, j+1);
            BOOST_CHECK(v1 == v2);
            
            if (v1 != v2) {
                std::cout << j+1 << std::endl;
                for(unsigned char c : v1)
                {
                    cout << hex << setw(2) << setfill('0') << (uint) c;
                }
                cout << "\n\n";
                for(unsigned char c : v2)
                {
                    cout << hex << setw(2) << setfill('0') << (uint) c;
                }
                cout << "\n==================";
                cout << "\n\n";

            }
        }
    
}