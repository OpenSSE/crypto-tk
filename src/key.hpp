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
#include <functional>

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
            
            template <class Hash, uint16_t key_size> friend class HMac;
            template <uint16_t NBYTES> friend class Prf;
            friend class Prg;
            
            
//            friend class TdpImpl;
            
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
                    throw std::bad_alloc::bad_alloc(); /* LCOV_EXCL_LINE */
                }
                
                random_bytes(N, content_);
                int err = sodium_mprotect_noaccess(content_);
                if (err == -1 && errno != ENOSYS) {
                    throw std::runtime_error("Error when locking memory: " + std::string(strerror(errno))); /* LCOV_EXCL_LINE */
                }
                is_locked_ = true;
            }

            /**
             *  @brief Constructor
             *
             *  Initializes the key with the byte array given as argument.
             *  The argument is set to zero.
             *
             *  @param key    The input byte array. When the constructor returns,
             *  key is set to 0.
             *
             *  @exception std::bad_alloc           Memory cannot be allocated.
             *  @exception std::runtime_error       Memory could not be protected.
             *  @exception std::invalid_argument    The input argument is NULL.
             */
            Key(uint8_t* const key)
            {
                if(key == NULL)
                {
                    throw std::invalid_argument("Invalid key: key == NULL");
                }
                content_ = static_cast<uint8_t*>(sodium_malloc(N));
                
                if(content_ == NULL)
                {
                    throw std::bad_alloc::bad_alloc(); /* LCOV_EXCL_LINE */
                }
                
                memcpy(content_, key, N); // copy the content of the input key
                sodium_memzero(key, N); // erase the content of the input key
                
                int err = sodium_mprotect_noaccess(content_);
                if (err == -1 && errno != ENOSYS) {
                    throw std::runtime_error("Error when locking memory: " + std::string(strerror(errno))); /* LCOV_EXCL_LINE */
                }
                is_locked_ = true;
            }

            /**
             *  @brief Constructor
             *
             *  Initializes the key using a callback given as input.
             *
             *  @param init_callback    The callback used to fill the key. It takes an uint8_t
             *  pointer as argument, with will point to the key content
             *
             *  @exception std::bad_alloc           Memory cannot be allocated.
             *  @exception std::runtime_error       Memory could not be protected.
             */
            Key(const std::function<void(uint8_t*)> &init_callback)
            {
                content_ = static_cast<uint8_t*>(sodium_malloc(N));
                
                if(content_ == NULL)
                {
                    throw std::bad_alloc::bad_alloc(); /* LCOV_EXCL_LINE */
                }
                
                init_callback(content_); // use the callback to fill the key
                
                int err = sodium_mprotect_noaccess(content_);
                if (err == -1 && errno != ENOSYS) {
                    throw std::runtime_error("Error when locking memory: " + std::string(strerror(errno))); /* LCOV_EXCL_LINE */
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
            void lock() const
            {
                if (content_ != NULL && !is_locked_) {
                    int err = sodium_mprotect_noaccess(content_);
                    if (err == -1 && errno != ENOSYS) {
                        throw std::runtime_error("Error when locking memory: " + std::string(strerror(errno))); /* LCOV_EXCL_LINE */
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
            void unlock() const
            {
                if (content_ != NULL && is_locked_) {
                    int err = sodium_mprotect_readonly(content_);
                    if (err == -1 && errno != ENOSYS) {
                        throw std::runtime_error("Error when locking memory: " + std::string(strerror(errno))); /* LCOV_EXCL_LINE */
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
            
            /**
             *  @brief Unlocks the key and gets its content
             *
             *  Returns a pointer to the key data.
             *  The caller has to relock the key after by calling unlock().
             *
             *  @exception std::runtime_error The memory cannot be accessed: it is absent (happens when
             *  the key has been modved) or cannot be unlocked.
             */
            const uint8_t* unlock_get() const
            {
                if (content_ == NULL) {
                    throw std::runtime_error("Memory is absent");
                }
                
                unlock();
                return content_;
            }
            
            
            uint8_t *content_; /*!< Pointer to the key content */
            mutable bool is_locked_; /*!< Flag denoting is the content_ point is read_protected */
            
            
            
        };
    }
}

