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

#include "gtest/gtest.h"

#define TEST_COUNT 100

TEST(prg, offset_1)
{
    std::array<uint8_t,sse::crypto::Prg::kKeySize> k{{0x00}};
    for (size_t i = 0; i < TEST_COUNT; i++) {
        
        
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        
        std::string out1, out2;
        
        out1 = prg.derive(32);
        out2 = prg.derive(16,16);
        
        ASSERT_TRUE(std::equal(out2.begin(), out2.end(), out1.begin()+16));
        
    }
}
TEST(prg, offset_2)
{
    std::array<uint8_t,sse::crypto::Prg::kKeySize> k{{0x00}};
    for (size_t i = 0; i < TEST_COUNT; i++) {
        
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        
        std::string out1, out2;
        
        out1 = prg.derive(32);
        out2 = prg.derive(15,16);
        
        ASSERT_TRUE(std::equal(out2.begin(), out2.end(), out1.begin()+15));
    }
}

TEST(prg, offset_3)
{
    std::array<uint8_t,sse::crypto::Prg::kKeySize> k{{0x00}};
    for (size_t i = 0; i < TEST_COUNT; i++) {
        
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        
        std::string out1, out2, out3, out4;
        
        out1 = prg.derive(33);
        out2 = prg.derive(17,16);
        out3 = prg.derive(32);
        out4 = prg.derive(16,16);
        
        ASSERT_TRUE(std::equal(out2.begin(), out2.end(), out1.begin()+17));
        ASSERT_TRUE(std::equal(out3.begin(), out3.end(), out1.begin()));
        ASSERT_TRUE(std::equal(out2.begin(), out2.end()-1, out4.begin()+1));
    }
}


TEST(prg, consistency_1)
{
    std::array<uint8_t,sse::crypto::Prg::kKeySize> k{{0x00}};
    
    for (size_t i = 0; i < TEST_COUNT; i++) {
        
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        
        std::string out1, out2;
        
        out1 = prg.derive(32);
        out2 = sse::crypto::Prg::derive(k,16,16);
        
        ASSERT_TRUE(std::equal(out2.begin(), out2.end(), out1.begin()+16));
    }
}

TEST(prg, consistency_2)
{
    std::array<uint8_t,sse::crypto::Prg::kKeySize> k{{0x00}};
    
    for (size_t i = 0; i < TEST_COUNT; i++) {
        
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        
        std::string out1, out2;
        
        out1 = prg.derive(31);
        out2 = sse::crypto::Prg::derive(k,16,15);
        
        ASSERT_TRUE(std::equal(out2.begin(), out2.end(), out1.begin()+16));
    }
}

TEST(prg, consistency_3)
{
    std::array<uint8_t,sse::crypto::Prg::kKeySize> k{{0x00}};

    for (size_t i = 0; i < TEST_COUNT; i++) {
                
        sse::crypto::random_bytes(k);
        
        sse::crypto::Prg prg(k);
        sse::crypto::Prg prg2(k.data());
        
        std::string out1, out2, out3, out4, out5, out6;
        std::string out7, out8, out10;
        
        std::array<uint8_t, 58> out_arr;
        uint8_t out_bytes[30];
        
        out1 = prg.derive(64);
        out2 = sse::crypto::Prg::derive(k,16,64-16);
        sse::crypto::Prg::derive(k.data(),64,out3);
        sse::crypto::Prg::derive(k,64,out4);
        out5 = sse::crypto::Prg::derive(k,64);
        sse::crypto::Prg::derive(k,15,10, out6);
        sse::crypto::Prg::derive(k.data(),6,58, out_arr.data());
      
        prg2.derive(64,out7);
        prg2.derive(18,46,out8);
        prg2.derive(34, 30, out_bytes);
        
        ASSERT_EQ(out2, std::string(out1.begin()+16, out1.end()));
        ASSERT_EQ(out1, out3);
        ASSERT_EQ(out1, out4);
        ASSERT_EQ(out1, out5);
        ASSERT_EQ(out6, std::string(out1.begin()+15, out1.begin()+15+10));
        ASSERT_EQ(std::string(out_arr.begin(), out_arr.end()),
                  std::string(out1.begin()+6, out1.begin()+6+58));
        
        ASSERT_EQ(out1, out7);
        ASSERT_EQ(out8, std::string(out1.begin()+18, out1.end()));
        ASSERT_EQ(std::string((char*)out_bytes, 30), std::string(out1.begin()+34, out1.end()));

    }
}

TEST(prg, exceptions)
{
    std::array<uint8_t,sse::crypto::Prg::kKeySize> k{{0x00}};
    sse::crypto::Prg prg(k);

    std::string out;
    
    ASSERT_THROW(prg.derive(0, out), std::invalid_argument);
    ASSERT_THROW(sse::crypto::Prg::derive(k.data(),0, out), std::invalid_argument);
    ASSERT_THROW(sse::crypto::Prg::derive((const uint8_t*)NULL,10, out), std::invalid_argument);
    
    ASSERT_THROW(sse::crypto::Prg p(NULL), std::invalid_argument);
}
