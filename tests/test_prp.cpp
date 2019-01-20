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

#if __AES__ || __ARM_FEATURE_CRYPTO /* Defined by gcc/clang when compiling for \
                                       AES-NI */

#include <sse/crypto/prp.hpp>
#include <sse/crypto/random.hpp>
#include <sse/crypto/wrapper.hpp>

#include <iomanip>
#include <iostream>
#include <string>

#include "gtest/gtest.h"

using namespace std;


TEST(prp, correctness)
{
    for (size_t i = 1; i <= 20 * 16; i++) {
        //        std::cout << i << std::endl;
        string in_enc = sse::crypto::random_string(i);
        string out_enc, out_dec;

        sse::crypto::Prp fpe;
        fpe.encrypt(in_enc, out_enc);

        ASSERT_EQ(in_enc.length(), out_enc.length());

        string in_dec = out_enc;

        fpe.decrypt(in_dec, out_dec);

        ASSERT_EQ(in_dec.length(), out_dec.length());
        ASSERT_EQ(in_enc, out_dec);
    }
}

TEST(prp, consistency_32)
{
    for (size_t i = 1; i <= 100; i++) {
        array<uint8_t, 48> key;

        sse::crypto::Prp fpe(
            sse::crypto::Key<sse::crypto::Prp::kKeySize>(key.data()));

        array<uint8_t, sizeof(uint32_t)> arr_32;

        sse::crypto::random_bytes(arr_32);

        std::string out_32_s_1
            = fpe.encrypt(std::string(arr_32.begin(), arr_32.end()));
        std::string out_32_s_2;
        uint32_t    in_32_i = static_cast<uint32_t>(arr_32[0])
                           + (static_cast<uint32_t>(arr_32[1]) << 8UL)
                           + (static_cast<uint32_t>(arr_32[2]) << 16UL)
                           + (static_cast<uint32_t>(arr_32[3]) << 24UL);

        fpe.encrypt(std::string(arr_32.begin(), arr_32.end()), out_32_s_2);
        uint32_t out_32_i = fpe.encrypt(in_32_i);


        ASSERT_EQ(out_32_s_1, out_32_s_2);
        ASSERT_EQ(out_32_s_1,
                  string(reinterpret_cast<char*>(&out_32_i), sizeof(uint32_t)));

        std::string dec_32_s_1 = fpe.decrypt(out_32_s_1);
        std::string dec_32_s_2;
        fpe.decrypt(out_32_s_2, dec_32_s_2);
        uint32_t dec_32_i = fpe.decrypt(out_32_i);

        ASSERT_EQ(dec_32_i, in_32_i);
        ASSERT_EQ(dec_32_s_1, dec_32_s_2);
        ASSERT_EQ(dec_32_s_1,
                  string(reinterpret_cast<char*>(&dec_32_i), sizeof(uint32_t)));
    }
}

TEST(prp, consistency_64)
{
    for (size_t i = 1; i <= 100; i++) {
        sse::crypto::Prp fpe;

        uint64_t in_64_i;
        sse::crypto::random_bytes(sizeof(uint64_t),
                                  reinterpret_cast<uint8_t*>(&in_64_i));
        std::string out_64_s_1 = fpe.encrypt(
            std::string(reinterpret_cast<char*>(&in_64_i), sizeof(uint64_t)));
        std::string out_64_s_2;

        fpe.encrypt(
            std::string(reinterpret_cast<char*>(&in_64_i), sizeof(uint64_t)),
            out_64_s_2);
        uint64_t out_64_i = fpe.encrypt_64(in_64_i);

        ASSERT_EQ(out_64_s_1, out_64_s_2);
        ASSERT_EQ(out_64_s_1,
                  string(reinterpret_cast<char*>(&out_64_i), sizeof(uint64_t)));

        std::string dec_64_s_1 = fpe.decrypt(out_64_s_1);
        std::string dec_64_s_2;
        fpe.decrypt(out_64_s_2, dec_64_s_2);
        uint64_t dec_64_i = fpe.decrypt_64(out_64_i);

        ASSERT_EQ(dec_64_i, in_64_i);
        ASSERT_EQ(dec_64_s_1, dec_64_s_2);
        ASSERT_EQ(dec_64_s_1,
                  string(reinterpret_cast<char*>(&dec_64_i), sizeof(uint64_t)));
    }
}

TEST(prp, wrapping)
{
    // Create new wrapper
    sse::crypto::Wrapper wrapper(
        (sse::crypto::Key<sse::crypto::Wrapper::kKeySize>()));

    // Create a Prg object
    sse::crypto::Prp base_prp;


    // wrap the object
    auto prp_rep = wrapper.wrap(base_prp);

    // unwrap the object
    sse::crypto::Prp unwrapped_prp = wrapper.unwrap<sse::crypto::Prp>(prp_rep);

    for (size_t i = 1; i <= 20 * 16; i++) {
        string in_enc = sse::crypto::random_string(i);
        string out_enc1, out_enc2, out_dec;

        base_prp.encrypt(in_enc, out_enc1);
        unwrapped_prp.encrypt(in_enc, out_enc2);

        ASSERT_EQ(in_enc.length(), out_enc1.length());
        ASSERT_EQ(in_enc.length(), out_enc2.length());
        EXPECT_EQ(out_enc1, out_enc2);

        string in_dec = out_enc1;
        base_prp.decrypt(in_dec, out_dec);

        ASSERT_EQ(in_dec.length(), out_dec.length());
        ASSERT_EQ(in_enc, out_dec);

        in_dec = out_enc2;
        base_prp.decrypt(in_dec, out_dec);

        ASSERT_EQ(in_dec.length(), out_dec.length());
        ASSERT_EQ(in_enc, out_dec);
    }
}
#else
#pragma message("PRP is disabled (requires support of AES instructions)")
#endif
