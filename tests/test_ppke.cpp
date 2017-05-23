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

#include "../src/ppke/GMPpke.h"
#include "../src/puncturable_enc.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <memory>


#include "gtest/gtest.h"

using namespace std;

#define SERIALIZATION_TEST_COUNT 500
#define SERIALIZATION_PUNCT_COUNT 50
#define ENCRYPTION_TEST_COUNT 10


TEST(relic, serialization_ZR)
{
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::ZR z((int)i);
        
        std::array<uint8_t, RELIC_BN_BYTES> bytes;
        z.writeBytes(bytes.data());
        
        relicxx::ZR y(bytes.data(), bytes.size());

        
        ASSERT_EQ(z, y);
    }
    
    relicxx::PairingGroup group;
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::ZR z = group.randomZR();
        
        std::array<uint8_t, RELIC_BN_BYTES> bytes;
        z.writeBytes(bytes.data());
        
        relicxx::ZR y(bytes.data(), bytes.size());
        
        
        ASSERT_EQ(z, y);
    }
 

}

TEST(relic, serialization_G1)
{
    relicxx::PairingGroup group;
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::G1 z = group.randomG1();
        
        std::array<uint8_t, relicxx::G1::kByteSize> bytes;
        z.writeBytes(bytes.data(), false);
        
        relicxx::G1 y(bytes.data(), false);
        
        
        ASSERT_EQ(z, y);
    }
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::G1 z = group.randomG1();
        
        std::array<uint8_t, relicxx::G1::kCompactByteSize> bytes;
        z.writeBytes(bytes.data(), true);
        
        relicxx::G1 y(bytes.data(), true);
        
        
        ASSERT_EQ(z, y);
    }
}

TEST(relic, serialization_G2)
{
    relicxx::PairingGroup group;
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::G2 z = group.randomG2();
        
        std::array<uint8_t, relicxx::G2::kByteSize> bytes;
        z.writeBytes(bytes.data(), false);
        
        relicxx::G2 y(bytes.data(), false);
        
        
        ASSERT_EQ(z, y);
    }
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::G2 z = group.randomG2();
        
        std::array<uint8_t, relicxx::G2::kCompactByteSize> bytes;
        z.writeBytes(bytes.data(), true);
        
        relicxx::G2 y(bytes.data(), true);
        
        
        ASSERT_EQ(z, y);
    }

}


TEST(ppke, serialization)
{
    sse::crypto::Prf<sse::crypto::kPPKEPrfOutputSize> key_prf;
    
    sse::crypto::Gmppke ppke;
    sse::crypto::GmppkePublicKey pk;
    sse::crypto::GmppkePrivateKey sk;
    sse::crypto::GmppkeSecretParameters sp;
    
    ppke.keygen(key_prf, pk, sk, sp);
    
    typedef uint64_t M_type;
    
    
    size_t current_p_count = 0;
    
    std::vector<sse::crypto::GmppkePrivateKeyShare> keyshares;
    keyshares.push_back(ppke.sk0Gen(key_prf, sp, 0));
    
    for ( ; current_p_count < SERIALIZATION_PUNCT_COUNT; current_p_count++) {
        sse::crypto::tag_type punctured_tag{{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};
        punctured_tag[15] = current_p_count&0xFF;
        punctured_tag[14] = (current_p_count>>8)&0xFF;
        punctured_tag[13] = (current_p_count>>16)&0xFF;
        punctured_tag[12] = (current_p_count>>24)&0xFF;
        punctured_tag[11] = (current_p_count>>32)&0xFF;
        punctured_tag[10] = (current_p_count>>40)&0xFF;
        punctured_tag[9] = (current_p_count>>48)&0xFF;
        punctured_tag[8] = 0xFF;
        
        
        auto share = ppke.skShareGen(key_prf, sp, current_p_count+1, punctured_tag);
        
        std::array<uint8_t, sse::crypto::GmppkePrivateKeyShare::kByteSize> share_data;
        share.writeBytes(share_data.data());
        
        sse::crypto::GmppkePrivateKeyShare serialized_share(share_data.data());
        
        ASSERT_EQ(share, serialized_share);
        
        keyshares.push_back(share);
    }

    keyshares[0] = ppke.sk0Gen(key_prf, sp, current_p_count);


    std::array<uint8_t, sse::crypto::GmppkePrivateKeyShare::kByteSize> share_data;
    keyshares[0].writeBytes(share_data.data());

    sse::crypto::GmppkePrivateKeyShare serialized_share(share_data.data());
    
    ASSERT_EQ(keyshares[0], serialized_share);


    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        M_type M;
        
        sse::crypto::random_bytes(sizeof(M_type), (uint8_t*) &M);
        
        sse::crypto::tag_type tag{{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};
        tag[0] = i&0xFF;
        tag[1] = (i>>8)&0xFF;
        tag[2] = (i>>16)&0xFF;
        tag[3] = (i>>24)&0xFF;
        tag[4] = (i>>32)&0xFF;
        tag[5] = (i>>40)&0xFF;
        tag[6] = (i>>48)&0xFF;
        tag[7] = (i>>56)&0xFF;
        
        auto ct = ppke.encrypt<M_type>(pk, M, tag);

        std::array<uint8_t, sse::crypto::GmmppkeCT<M_type>::kByteSize> ct_data;
        ct.writeBytes(ct_data.data());
        sse::crypto::GmmppkeCT<M_type> serialized_ct(ct_data.data());

        ASSERT_EQ(ct, serialized_ct);
    }
}

TEST(ppke, correctness)
{
    sse::crypto::Prf<sse::crypto::kPPKEPrfOutputSize> key_prf;
    
    sse::crypto::Gmppke ppke;
    sse::crypto::GmppkePublicKey pk;
    sse::crypto::GmppkePrivateKey sk;
    sse::crypto::GmppkeSecretParameters sp;
    
    ppke.keygen(key_prf, pk, sk, sp);
    
    typedef uint64_t M_type;
    
    
    std::vector<size_t> puncture_count_list = {0, 1, 2, 5, 10, 15, 20, 30, 40};
    
    size_t current_p_count = 0;
    
    std::vector<sse::crypto::GmppkePrivateKeyShare> keyshares;
    keyshares.push_back(ppke.sk0Gen(key_prf, sp, 0));
    
    for (size_t p : puncture_count_list) {
        
        if (p > current_p_count) {
            
            // add new punctures
            for ( ; current_p_count < p; current_p_count++) {
                sse::crypto::tag_type punctured_tag{{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};
                punctured_tag[15] = current_p_count&0xFF;
                punctured_tag[14] = (current_p_count>>8)&0xFF;
                punctured_tag[13] = (current_p_count>>16)&0xFF;
                punctured_tag[12] = (current_p_count>>24)&0xFF;
                punctured_tag[11] = (current_p_count>>32)&0xFF;
                punctured_tag[10] = (current_p_count>>40)&0xFF;
                punctured_tag[9] = (current_p_count>>48)&0xFF;
                punctured_tag[8] = 0xFF;
                
                auto share = ppke.skShareGen(key_prf, sp, current_p_count+1, punctured_tag);
                
                keyshares.push_back(share);
            }
            
            keyshares[0] = ppke.sk0Gen(key_prf, sp, current_p_count);
            
        }
        
        for (size_t i = 0; i < ENCRYPTION_TEST_COUNT; i++) {
            M_type M;
            
            sse::crypto::random_bytes(sizeof(M_type), (uint8_t*) &M);
            
            sse::crypto::tag_type tag{{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};
            tag[0] = i&0xFF;
            tag[1] = (i>>8)&0xFF;
            tag[2] = (i>>16)&0xFF;
            tag[3] = (i>>24)&0xFF;
            tag[4] = (i>>32)&0xFF;
            tag[5] = (i>>40)&0xFF;
            tag[6] = (i>>48)&0xFF;
            tag[7] = (i>>56)&0xFF;
            
            auto ct = ppke.encrypt<M_type>(pk, M, tag);
            auto ct2 = ppke.encrypt<M_type>(sp, M, tag);
            M_type dec_M = ppke.decrypt(sse::crypto::GmppkePrivateKey(keyshares), ct2);
            M_type dec_M2 = ppke.decrypt(sse::crypto::GmppkePrivateKey(keyshares), ct2);
            
            ASSERT_EQ(M, dec_M);
            ASSERT_EQ(M, dec_M2);
        }
    }
}

TEST(puncturable, correctness)
{
    std::array<uint8_t, 16> master_key;
    for (size_t i = 0; i < master_key.size(); i++) {
        master_key[i] = 1 << i;
    }
    
    sse::crypto::PuncturableEncryption encryptor(master_key);

    typedef uint64_t M_type;
    
    
    size_t current_p_count = 0;
    
    sse::crypto::punct::punctured_key_type punctured_key;
    punctured_key.push_back(encryptor.initial_keyshare(0));
    
    for ( ; current_p_count < 5; current_p_count++) {
        sse::crypto::tag_type punctured_tag{{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};
        punctured_tag[15] = current_p_count&0xFF;
        punctured_tag[14] = (current_p_count>>8)&0xFF;
        punctured_tag[13] = (current_p_count>>16)&0xFF;
        punctured_tag[12] = (current_p_count>>24)&0xFF;
        punctured_tag[11] = (current_p_count>>32)&0xFF;
        punctured_tag[10] = (current_p_count>>40)&0xFF;
        punctured_tag[9] = (current_p_count>>48)&0xFF;
        punctured_tag[8] = 0xFF;
        
        
        auto share = encryptor.inc_puncture(current_p_count+1, punctured_tag);
        
        punctured_key.push_back(share);
    }
    
    punctured_key[0] = encryptor.initial_keyshare(current_p_count);
    
    
    sse::crypto::PuncturableDecryption decryptor(punctured_key);

    for (size_t i = 0; i < ENCRYPTION_TEST_COUNT; i++) {
        M_type M = i, dec_M;
        
//        sse::crypto::random_bytes(sizeof(M_type), (uint8_t*) &M);
        
        sse::crypto::tag_type tag{{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};
        tag[0] = i&0xFF;
        tag[1] = (i>>8)&0xFF;
        tag[2] = (i>>16)&0xFF;
        tag[3] = (i>>24)&0xFF;
        tag[4] = (i>>32)&0xFF;
        tag[5] = (i>>40)&0xFF;
        tag[6] = (i>>48)&0xFF;
        tag[7] = (i>>56)&0xFF;
        
        auto ct = encryptor.encrypt(M, tag);
        bool success = decryptor.decrypt(ct, dec_M);

        ASSERT_TRUE(success);
        ASSERT_EQ(M, dec_M);

    }
}
