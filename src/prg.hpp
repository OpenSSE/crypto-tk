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


#include <cstdint>

#include <array>
#include <string>
#include <vector>

#include <sodium/utils.h>

namespace sse
{
    namespace crypto
    {
        
        /*****
         * Prg class
         *
         * Opaque class for a pseudo random generator.
         *
         * It is constructed with a blockcipher in CTR mode.
         ******/
        
        class Prg
        {
        public:
            static constexpr uint8_t kKeySize = 32;
            
            Prg() = delete;
            Prg(Key<kKeySize>&& k);

            // we should not be able to duplicate Prg objects
            Prg(const Prg& c) = delete;
            Prg(Prg& c) = delete;
            Prg(const Prg&& c) = delete;
            Prg(Prg&& c) = delete;
            
                        
            ~Prg();
            
            // Avoid any assignement of Prg objects
            Prg& operator=(const Prg& h) = delete;
            Prg& operator=(Prg& h) = delete;
            


            void derive(const size_t len, std::string &out) const;
            std::string derive(const size_t len) const;

            void derive(const uint32_t offset, const size_t len, std::string &out) const;
            std::string derive(const uint32_t offset, const size_t len) const;
            void derive(const uint32_t offset, const size_t len, unsigned char* out) const;

            static void derive(Key<kKeySize>&& k, const size_t len, std::string &out);
            static void derive(Key<kKeySize>&& k, const uint32_t offset, const size_t len, std::string &out);
            static std::string derive(Key<kKeySize>&& k, const size_t len);
            static std::string derive(Key<kKeySize>&& k, const uint32_t offset, const size_t len);

            template <size_t K> Key<K> derive_key( const uint16_t key_offset);

            template <size_t K> std::vector<Key<K> > derive_keys(const uint16_t n_keys, const uint16_t key_offset = 0);
            
            /* Static functions */
            
            static void derive(Key<kKeySize>&& k, const uint32_t offset, const size_t len, unsigned char* out);

            template <size_t N> static inline void derive(Key<kKeySize>&& k, const uint32_t offset, std::array<uint8_t, N> &out)
            {
                derive(std::move(k), offset, N, out.data());
            }

            template <size_t K> static Key<K> derive_key(Key<kKeySize>&& k, const uint16_t key_offset);

            template <size_t K> static std::vector<Key<K> > derive_keys(Key<kKeySize>&& k, const uint16_t n_keys, const uint16_t key_offset = 0);


        private:
            class PrgImpl; // not defined in the header
            PrgImpl *prg_imp_; // opaque pointer
        };

        template <size_t K> Key<K> Prg::derive_key(const uint16_t key_offset)
        {
            static_assert(K < SIZE_MAX, "K is too large: K < SIZE_MAX");
            
            if (key_offset > (size_t) 0U && K >= (size_t) SIZE_MAX / key_offset) {
                throw std::invalid_argument("Key offset too large. key_offset*K >= SIZE_MAX."); /* LCOV_EXCL_LINE */
            }
            
            auto fill_callback = [this,key_offset](uint8_t* key_content)
            {
                this->derive(key_offset*K,K,key_content);
            };
            
            return Key<K>(fill_callback);
        }

        template <size_t K> Key<K> Prg::derive_key(Key<Prg::kKeySize>&& k, const uint16_t key_offset)
        {
            static_assert(K < SIZE_MAX, "K is too large: K < SIZE_MAX");
            
            if (key_offset > (size_t) 0U && K >= (size_t) SIZE_MAX / key_offset) {
                throw std::invalid_argument("Key offset too large. key_offset*K >= SIZE_MAX."); /* LCOV_EXCL_LINE */
            }
            
            auto fill_callback = [&k,key_offset](uint8_t* key_content)
            {
                derive(std::move(k),key_offset*K,K,key_content);
            };
            
            return Key<K>(fill_callback);
        }

        template <size_t K> std::vector<Key<K> > Prg::derive_keys(const uint16_t n_keys, const uint16_t key_offset)
        {
            if (n_keys > (size_t) 0U && K >= (size_t) SIZE_MAX / n_keys) {
                throw std::invalid_argument("Too many keys to derive. n_keys*K >= SIZE_MAX."); /* LCOV_EXCL_LINE */
            }
            if (key_offset > (size_t) 0U && K >= (size_t) SIZE_MAX / key_offset) {
                throw std::invalid_argument("Key offset too large. key_offset*K >= SIZE_MAX."); /* LCOV_EXCL_LINE */
            }
            
            if (n_keys == 0) {
                return std::vector<Key<K> >(); // return empty vector
            }

            uint8_t* key_buffer = (uint8_t*)sodium_allocarray(n_keys, K);
            
            this->derive(key_offset*K, n_keys*K, key_buffer);
            
            std::vector<Key<K> > derived_keys;
            
            for (uint16_t i = 0; i < n_keys; i++) {
                derived_keys.push_back(Key<K>(key_buffer + i*K));
            }
            
            sodium_free(key_buffer);
            
            return derived_keys;
        }

        
        template <size_t K> std::vector<Key<K> > Prg::derive_keys(Key<kKeySize>&& k, const uint16_t n_keys, const uint16_t key_offset)
        {
            if (k.is_empty()) {
                throw std::invalid_argument("PRG input key is empty");
            }
            if (n_keys == 0) {
                return std::vector<Key<K> >(); // return empty vector
            }
            if (n_keys > (size_t) 0U && K >= (size_t) SIZE_MAX / n_keys) {
                throw std::invalid_argument("Too many keys to derive. n_keys*K >= SIZE_MAX."); /* LCOV_EXCL_LINE */
            }
            if (key_offset > (size_t) 0U && K >= (size_t) SIZE_MAX / key_offset) {
                throw std::invalid_argument("Key offset too large. key_offset*K >= SIZE_MAX."); /* LCOV_EXCL_LINE */
            }

            
            uint8_t* key_buffer = (uint8_t*)sodium_allocarray(n_keys, K);
            
            derive(std::move(k), key_offset*K, n_keys*K, key_buffer);
            
            std::vector<Key<K> > derived_keys;
            
            for (uint16_t i = 0; i < n_keys; i++) {
                derived_keys.push_back(Key<K>(key_buffer + i*K));
            }
            
            sodium_free(key_buffer);
            
            return derived_keys;
        }
        
    }
}

/* Instantiation declaration of some of the templates */

#define INSTANTIATE_PRG_TEMPLATE_EXTERN(N) \
namespace sse { \
namespace crypto { \
extern template std::vector<Key<N> > Prg::derive_keys(const uint16_t n_keys, const uint16_t key_offset); \
extern template Key<N> Prg::derive_key( const uint16_t key_offset); \
extern template Key<N> Prg::derive_key(Key<kKeySize>&& k, const uint16_t key_offset); \
extern template std::vector<Key<N> > Prg::derive_keys(Key<kKeySize>&& k, const uint16_t n_keys, const uint16_t key_offset = 0); \
} \
}

#define INSTANTIATE_PRG_TEMPLATE(N) \
namespace sse { \
namespace crypto { \
template std::vector<Key<N> > Prg::derive_keys(const uint16_t n_keys, const uint16_t key_offset); \
template Key<N> Prg::derive_key( const uint16_t key_offset); \
template Key<N> Prg::derive_key(Key<kKeySize>&& k, const uint16_t key_offset); \
template std::vector<Key<N> > Prg::derive_keys(Key<kKeySize>&& k, const uint16_t n_keys, const uint16_t key_offset = 0); \
} \
}


INSTANTIATE_PRG_TEMPLATE_EXTERN(16)
INSTANTIATE_PRG_TEMPLATE_EXTERN(32)

