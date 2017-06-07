//
//  ppke.hpp
//  libsse_crypto
//
//  Created by Raphael Bost on 14/05/2017.
//  Copyright © 2017 VSSE project. All rights reserved.
//

#pragma once

#include <string>
#include <array>
#include <vector>

namespace sse
{
    
    namespace crypto
    {
        
//        class PpkeHandler;
//        thread_local PpkeHandler ppke_handler__;

        /*****
         * Ppke class
         *
         * Opaque class for Puncturable Public Key Encryption.
         *
         * PPKE is implemented using Green-Miers scheme.
         ******/
        
        namespace punct
        {
            constexpr static size_t kTagSize = 16;
            typedef std::array<uint8_t, kTagSize> tag_type;
            
            constexpr static size_t kKeyShareSize = 211;
            typedef std::array<uint8_t, kKeyShareSize> key_share_type;
            typedef std::vector<key_share_type> punctured_key_type;
            
            const static size_t kMasterKeySize = 16;
            typedef std::array<uint8_t, kMasterKeySize> master_key_type;
            
            const static size_t kCiphertextSize = 90;
            typedef std::array<uint8_t, kCiphertextSize> ciphertext_type;

            
            inline tag_type extract_tag(const key_share_type& keyshare)
            {
                tag_type tag;
                std::copy(keyshare.end()-kTagSize, keyshare.end(), tag.begin());
                return tag;
            }
            
            inline tag_type extract_tag(const ciphertext_type& ciphertext)
            {
                tag_type tag;
                std::copy(ciphertext.end()-kTagSize, ciphertext.end(), tag.begin());
                return tag;
            }
            
        }
        
        class PuncturableEncryption
        {
        public:
            
            PuncturableEncryption(const punct::master_key_type& key);
            ~PuncturableEncryption();
            
            punct::ciphertext_type encrypt(const uint64_t m, const punct::tag_type &tag);
            punct::key_share_type initial_keyshare(const size_t d);
            punct::key_share_type inc_puncture(const size_t d, const punct::tag_type &tag);

        private:
            class PEncImpl; // not defined in the header
            PEncImpl *penc_imp_; // opaque pointer
        };

        class PuncturableDecryption
        {
        public:
            PuncturableDecryption(const punct::punctured_key_type& punctured_key);
            ~PuncturableDecryption();

            bool decrypt(const punct::ciphertext_type &ct, uint64_t &m);

        private:
            class PDecImpl; // not defined in the header
            PDecImpl *pdec_imp_; // opaque pointer
        };

    }
}
