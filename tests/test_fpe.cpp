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

#include "../src/fpe.hpp"
#include "../src/random.hpp"


#include <iostream>
#include <iomanip>
#include <string>

#include "gtest/gtest.h"

using namespace std;


TEST(fpe, correctness) {
    
    for (size_t i = 1; i <= 20*16; i++) {
        
        string in_enc = sse::crypto::random_string(i);
        string out_enc, out_dec;
        
        array<uint8_t,sse::crypto::Fpe::kKeySize> k;
        sse::crypto::random_bytes(k);
        
        sse::crypto::Fpe fpe(k);
        fpe.encrypt(in_enc, out_enc);
        
        ASSERT_EQ(in_enc.length(), out_enc.length());
        
        string in_dec = string(out_enc);
        
        fpe.decrypt(in_dec, out_dec);
        
        ASSERT_EQ(in_dec.length(), out_dec.length());
        ASSERT_EQ(in_enc, out_dec);
    }
}

TEST(fpe, consistency_32) {
    
    for (size_t i = 1; i <= 100; i++) {
        sse::crypto::Fpe fpe;
        
        array<uint8_t, sizeof(uint32_t)> arr_32;
        
        sse::crypto::random_bytes(arr_32);
        
        std::string out_32_s_1 = fpe.encrypt(std::string(arr_32.begin(), arr_32.end()));
        std::string out_32_s_2;
        uint32_t in_32_i = arr_32[0] + (arr_32[1]<<8) + (arr_32[2]<<16) + (arr_32[3]<<24) ;
        
        fpe.encrypt(std::string(arr_32.begin(), arr_32.end()), out_32_s_2);
        uint32_t out_32_i = fpe.encrypt(in_32_i);
        
        
        ASSERT_EQ(out_32_s_1, out_32_s_2);
        ASSERT_EQ(out_32_s_1, string((char*) &out_32_i, sizeof(uint32_t)));

        std::string dec_32_s_1 = fpe.decrypt(out_32_s_1);
        std::string dec_32_s_2;
        fpe.decrypt(out_32_s_2, dec_32_s_2);
        uint32_t dec_32_i = fpe.decrypt(out_32_i);

        ASSERT_EQ(dec_32_i, in_32_i);
        ASSERT_EQ(dec_32_s_1, dec_32_s_2);
        ASSERT_EQ(dec_32_s_1, string((char*) &dec_32_i, sizeof(uint32_t)));

    }
}

TEST(fpe, consistency_64) {
    
    for (size_t i = 1; i <= 100; i++) {
        sse::crypto::Fpe fpe;
        
        uint64_t in_64_i;
        sse::crypto::random_bytes(sizeof(uint64_t),(uint8_t *) &in_64_i);
        std::string out_64_s_1 = fpe.encrypt(std::string((char*) &in_64_i, sizeof(uint64_t)));
        std::string out_64_s_2;
        
        fpe.encrypt(std::string((char*) &in_64_i, sizeof(uint64_t)), out_64_s_2);
        uint64_t out_64_i = fpe.encrypt_64(in_64_i);
        
        ASSERT_EQ(out_64_s_1, out_64_s_2);
        ASSERT_EQ(out_64_s_1, string((char*) &out_64_i, sizeof(uint64_t)));
        
        std::string dec_64_s_1 = fpe.decrypt(out_64_s_1);
        std::string dec_64_s_2;
        fpe.decrypt(out_64_s_2, dec_64_s_2);
        uint64_t dec_64_i = fpe.decrypt_64(out_64_i);
        
        ASSERT_EQ(dec_64_i, in_64_i);
        ASSERT_EQ(dec_64_s_1, dec_64_s_2);
        ASSERT_EQ(dec_64_s_1, string((char*) &dec_64_i, sizeof(uint64_t)));
    }
}
