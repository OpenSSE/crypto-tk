//
//  key.hpp
//  libsse_crypto
//
//  Created by Raphael Bost on 23/10/2017.
//  Copyright © 2017 VSSE project. All rights reserved.
//

#pragma once

#include "sodium/utils.h"
#include "random.hpp"

#include <cstdint>
#include <cerrno>
#include <cstring>

#include <new>

namespace sse {
    namespace crypto {
        
        void test_keys();

        /** @class Key
         *  @brief A class for keys represented as byte strings.
         *
         *  Keys are precious elements that must be protected
         *  The key template provides all the necessary tools to securely manage keys
         *  in OpenSSE's cryptographic toolkit.
         *
         *  The Key<N> template wraps a pointer to memory allocated with sodium_malloc.
         *  It in particular means that the key memory is protected with no-access pages
         *  and a canary.
         *
         *  Keys can only be accessed through a handler, which can only be used by the
         *  cryptographic toolkit: the toolkit user is not meant to read or write the keys.
         *  Also, a key is not copyable, only movable.
         *
         *  @tparam N       Byte length of the key
         *
         */
        
        template <size_t N>
        class Key {
            // declare all the friend classes and functions
            friend void test_keys();
            
            template <class Hash> friend class HMAC;
            template <uint16_t NBYTES> friend class Prf;
        public:
            /**
             *  @brief Constructor
             *
             *  Initializes the key with random bytes.
             *
             *  @exception std::bad_alloc       Memory cannot be allocated.
             *  @exception std::runtime_erro    Memory could not be protected.
             */
            Key()
            {
                content_ = static_cast<uint8_t*>(sodium_malloc(N));
                
                if( content_ == NULL)
                {
                    throw std::bad_alloc::bad_alloc();
                }
                
                random_bytes(N, content_);
                int err = sodium_mprotect_noaccess(content_);
                if (err == -1 && errno != ENOSYS) {
                    throw std::runtime_error("Error when locking memory: " + std::string(strerror(errno)));
                }
                is_locked_ = true;
            }
            
            Key(Key<N>& k) = delete;
            
            /**
             *  @brief Move constructor
             *
             *  @param k    The moved key
             *
             */
            Key(Key<N>&& k):
            content_(k.content_), is_locked_(k.is_locked_)
            {
                k.content_ = NULL;
                k.is_locked_ = true;
            }
            
            /**
             *  @brief Destructor
             *
             *  Erase the content of the key and frees the memory.
             *
             */
            ~Key()
            {
                if (content_ != NULL) {
                    sodium_free(content_);
                    content_ = NULL;
                    is_locked_ = true;
                }
            }
            
        private:
            
            /**
             *  @brief Locks the key
             *
             *  Makes the key content neither readable or writable.
             *
             *  @exception std::runtime_error Memory cannot be locked.
             */
            void lock()
            {
                if (content_ != NULL && !is_locked_) {
                    int err = sodium_mprotect_noaccess(content_);
                    if (err == -1 && errno != ENOSYS) {
                        throw std::runtime_error("Error when locking memory: " + std::string(strerror(errno)));
                    }
                    is_locked_ = true;
                }
            }
            
            /**
             *  @brief Unlocks the key
             *
             *  Makes the key content readable (but not writable).
             *
             *  @exception std::runtime_error Memory cannot be locked.
             */
            void unlock()
            {
                if (content_ != NULL && is_locked_) {
                    int err = sodium_mprotect_readonly(content_);
                    if (err == -1 && errno != ENOSYS) {
                        throw std::runtime_error("Error when locking memory: " + std::string(strerror(errno)));
                    }
                    is_locked_ = false;
                }
            }
            
            /**
             *  @brief Gets the key content
             *
             *  Returns a pointer to the key data.
             *
             *  @exception std::runtime_error The memory cannot be accessed: it is absent or locked.
             */
            const uint8_t* data() const
            {
                if (is_locked_) {
                    throw std::runtime_error("Memory is locked");
                }
                return content_;
            }
            
            uint8_t *content_;
            bool is_locked_;
            
            
            
        };
    }
}

