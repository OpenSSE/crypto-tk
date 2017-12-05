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

#pragma once

#include "key.hpp"

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
            using tag_type = std::array<uint8_t, kTagSize>;
            
            constexpr static size_t kKeyShareSize = 211;
            using key_share_type = std::array<uint8_t, kKeyShareSize>;
            using punctured_key_type = std::vector<key_share_type>;
            
            const static size_t kMasterKeySize = 32;
            using master_key_type = Key<kMasterKeySize>;
            
            const static size_t kCiphertextSize = 90;
            using ciphertext_type = std::array<uint8_t, kCiphertextSize>;

            
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
            
            PuncturableEncryption(punct::master_key_type&& key);
            PuncturableEncryption(const PuncturableEncryption&) = delete;
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
            PuncturableDecryption(const PuncturableDecryption&) = delete;
            ~PuncturableDecryption();

            bool decrypt(const punct::ciphertext_type &ct, uint64_t &m);

        private:
            class PDecImpl; // not defined in the header
            PDecImpl *pdec_imp_; // opaque pointer
        };

    }
}
