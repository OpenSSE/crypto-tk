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

#include "../src/prg.hpp"
#include "../src/random.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <algorithm>
#include <boost/test/unit_test.hpp>

#define TEST_COUNT 2

void test_prg()
{
    for (size_t i = 0; i < TEST_COUNT; i++) {
        
        std::array<uint8_t,sse::crypto::Prg::kKeySize> k{};
        
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        
        std::string out1, out2;
        
        out1 = prg.derive(32);
        out2 = prg.derive(16,16);
        
        BOOST_CHECK(std::equal(out2.begin(), out2.end(), out1.begin()+16));
        
        for(uint8_t c : out1)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
        }
        std::cout << std::endl;
        for(uint8_t c : out2)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
        }
        std::cout << std::endl;
        std::cout << std::endl;

    }
    for (size_t i = 0; i < TEST_COUNT; i++) {
        
        std::array<uint8_t,sse::crypto::Prg::kKeySize> k{};
        
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        
        std::string out1, out2;
        
        out1 = prg.derive(32);
        out2 = prg.derive(15,16);
        
        for(uint8_t c : out1)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
        }
        std::cout << std::endl;
        for(uint8_t c : out2)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
        }
        std::cout << std::endl;
        std::cout << std::endl;

        BOOST_CHECK(std::equal(out2.begin(), out2.end(), out1.begin()+15));
    }
    for (size_t i = 0; i < TEST_COUNT; i++) {
        
        std::array<uint8_t,sse::crypto::Prg::kKeySize> k{};
        
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        
        std::string out1, out2;
        
        out1 = prg.derive(33);
        out2 = prg.derive(17,16);
        
        for(uint8_t c : out1)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
        }
        std::cout << std::endl;
        for(uint8_t c : out2)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
        }
        std::cout << std::endl;
        std::cout << std::endl;

        BOOST_CHECK(std::equal(out2.begin(), out2.end(), out1.begin()+17));
    }
}


void test_prg_consistency()
{
    for (size_t i = 0; i < TEST_COUNT; i++) {
        
        std::array<uint8_t,sse::crypto::Prg::kKeySize> k{};
        
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        
        std::string out1, out2;
        
        out1 = prg.derive(32);
        out2 = sse::crypto::Prg::derive(k,16,16);
        
        for(uint8_t c : out1)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
        }
        std::cout << std::endl;
        for(uint8_t c : out2)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
        }
        std::cout << std::endl;
        std::cout << std::endl;
        
        BOOST_CHECK(std::equal(out2.begin(), out2.end(), out1.begin()+16));
    }
    for (size_t i = 0; i < TEST_COUNT; i++) {
        
        std::array<uint8_t,sse::crypto::Prg::kKeySize> k{};
        
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        
        std::string out1, out2;
        
        out1 = prg.derive(64);
        out2 = sse::crypto::Prg::derive(k,16,64-16);
        
        for(uint8_t c : out1)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
        }
        std::cout << std::endl;
        for(uint8_t c : out2)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (uint) c;
        }
        std::cout << std::endl;
        std::cout << std::endl;
        
        BOOST_CHECK(std::equal(out2.begin(), out2.end(), out1.begin()+16));
    }
}
