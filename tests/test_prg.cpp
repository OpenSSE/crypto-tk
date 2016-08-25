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

#include "../tests/test_prg.hpp"

#include "../src/prg.hpp"
#include "../src/random.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <algorithm>

#include "boost_test_include.hpp"

#define TEST_COUNT 10

void test_prg()
{
    std::array<uint8_t,sse::crypto::Prg::kKeySize> k{{0x00}};
    for (size_t i = 0; i < TEST_COUNT; i++) {
        
        
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        
        std::string out1, out2;
        
        out1 = prg.derive(32);
        out2 = prg.derive(16,16);
        
        BOOST_CHECK(std::equal(out2.begin(), out2.end(), out1.begin()+16));

    }
    for (size_t i = 0; i < TEST_COUNT; i++) {
        
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        
        std::string out1, out2;
        
        out1 = prg.derive(32);
        out2 = prg.derive(15,16);
        
        BOOST_CHECK(std::equal(out2.begin(), out2.end(), out1.begin()+15));
    }
    for (size_t i = 0; i < TEST_COUNT; i++) {
        
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        
        std::string out1, out2, out3, out4;
        
        out1 = prg.derive(33);
        out2 = prg.derive(17,16);
        out3 = prg.derive(32);
        out4 = prg.derive(16,16);
        
        BOOST_CHECK(std::equal(out2.begin(), out2.end(), out1.begin()+17));
        BOOST_CHECK(std::equal(out3.begin(), out3.end(), out1.begin()));
        BOOST_CHECK(std::equal(out2.begin(), out2.end()-1, out4.begin()+1));
    }
}


void test_prg_consistency()
{
    std::array<uint8_t,sse::crypto::Prg::kKeySize> k{{0x00}};
    
    for (size_t i = 0; i < TEST_COUNT; i++) {
        
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        
        std::string out1, out2;
        
        out1 = prg.derive(32);
        out2 = sse::crypto::Prg::derive(k,16,16);
        
        BOOST_CHECK(std::equal(out2.begin(), out2.end(), out1.begin()+16));
    }
    for (size_t i = 0; i < TEST_COUNT; i++) {
                
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        
        std::string out1, out2;
        
        out1 = prg.derive(64);
        out2 = sse::crypto::Prg::derive(k,16,64-16);
      
        BOOST_CHECK(std::equal(out2.begin(), out2.end(), out1.begin()+16));
    }
}
