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

#include "../src/block_hash.hpp"

#include <array>
#include <iostream>
#include <iomanip>
#include <string>
#include <algorithm>

#include "gtest/gtest.h"


TEST(block_hash_aes, test_vector)
{
    std::array<uint8_t, 16> in_array = {{0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}};

    std::array<uint8_t, 16> expected_out = {{0x51, 0x16, 0xc5, 0x56, 0x23, 0x3a, 0xa9, 0xf6, 0x41, 0xa3, 0xb4, 0xe2, 0x57, 0xf5, 0xf8, 0xbd}};

    std::string in(in_array.begin(), in_array.end());
    
    std::string  out = sse::crypto::BlockHash::hash(in);
    

    ASSERT_EQ(out, std::string(expected_out.begin(), expected_out.end()));

}


TEST(block_hash_aes, test_vector_trunc)
{
    std::array<uint8_t, 16> in_array = {{0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}};
    
    std::array<uint8_t, 16> expected_out = {{0x51, 0x16, 0xc5, 0x56, 0x23, 0x3a, 0xa9, 0xf6, 0x41, 0xa3, 0xb4, 0xe2, 0x57, 0xf5, 0xf8, 0xbd}};
    std::string expected_out_string = std::string((char *)expected_out.data(), 10);
    
    std::string in(in_array.begin(), in_array.end());
    
    std::string  out = sse::crypto::BlockHash::hash(in, 10);
    
    
    ASSERT_EQ(out, expected_out_string);
    
}

TEST(block_hash_aes, test_vector_array_trunc)
{
    constexpr size_t test_size = 13;
    std::array<uint8_t, 16> in_array = {{0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}};
    
    std::array<uint8_t, 16> expected_out = {{0x51, 0x16, 0xc5, 0x56, 0x23, 0x3a, 0xa9, 0xf6, 0x41, 0xa3, 0xb4, 0xe2, 0x57, 0xf5, 0xf8, 0xbd}};
    std::string expected_out_string = std::string((char *)expected_out.data(), test_size);
    
    uint8_t out[test_size];
    
//    std::string in(in_array.begin(), in_array.end());
    
    sse::crypto::BlockHash::hash(in_array.data(), test_size, out);
    
    std::string out_string((char *)out, test_size);

    
    ASSERT_EQ(out_string, expected_out_string);
    
}

TEST(block_hash_aes, mult_hash)
{
    std::array<uint8_t, 16> in_array = {{0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}};
    
    std::array<uint8_t, 16> expected_out = {{0x51, 0x16, 0xc5, 0x56, 0x23, 0x3a, 0xa9, 0xf6, 0x41, 0xa3, 0xb4, 0xe2, 0x57, 0xf5, 0xf8, 0xbd}};
    
    
    for (size_t i = 1; i <= 32; i++) {
        uint8_t *in, *out;
        in = new uint8_t [i*16];
        
        // copy the input array i types
        for (size_t j = 0; j < i; j++) {
            memcpy(in+j*16, in_array.data(), 16);
            std::string in_string((char *)in+j*16, 16);
            ASSERT_EQ(in_string, std::string(in_array.begin(), in_array.end()));
        }
        out = new uint8_t [i*16];
        sse::crypto::BlockHash::mult_hash(in, i*16, out);
        
        for (size_t j = 0; j < i; j++) {
            std::string out_string((char *)out+j*16, 16);
            ASSERT_EQ(out_string, std::string(expected_out.begin(), expected_out.end()));
        }
        
        delete [] in;
        delete [] out;
    }
}

TEST(block_hash_aes, exceptions)
{
    std::array<uint8_t, 16> in_array = {{0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}};
    std::string in(in_array.begin(), in_array.end());
    std::string out;
    
    ASSERT_THROW(sse::crypto::BlockHash::hash(in, 18, out), std::invalid_argument);
    ASSERT_THROW(sse::crypto::BlockHash::hash(in, 0, out), std::invalid_argument);

    ASSERT_THROW(sse::crypto::BlockHash::hash(reinterpret_cast<const uint8_t*>(in.data()), 18, reinterpret_cast<unsigned char*>(const_cast<char*>(out.data()))), std::invalid_argument);
    ASSERT_THROW(sse::crypto::BlockHash::hash(reinterpret_cast<const uint8_t*>(in.data()), 0, reinterpret_cast<unsigned char*>(const_cast<char*>(out.data()))), std::invalid_argument);
    ASSERT_THROW(sse::crypto::BlockHash::hash(NULL, 16, reinterpret_cast<unsigned char*>(const_cast<char*>(out.data()))), std::invalid_argument);
    ASSERT_THROW(sse::crypto::BlockHash::hash(reinterpret_cast<const uint8_t*>(in.data()), 16, NULL), std::invalid_argument);

    ASSERT_THROW(sse::crypto::BlockHash::mult_hash(reinterpret_cast<const uint8_t*>(in.data()), 18, reinterpret_cast<unsigned char*>(const_cast<char*>(out.data()))), std::invalid_argument);
    ASSERT_THROW(sse::crypto::BlockHash::mult_hash(NULL, 16, reinterpret_cast<unsigned char*>(const_cast<char*>(out.data()))), std::invalid_argument);
    ASSERT_THROW(sse::crypto::BlockHash::mult_hash(reinterpret_cast<const uint8_t*>(in.data()), 16, NULL), std::invalid_argument);

}
