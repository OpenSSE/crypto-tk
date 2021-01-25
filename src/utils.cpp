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

#include "utils.hpp"

#include "ppke/relic_wrapper/relic_api.h"
#include "prp.hpp"

#include <pthread.h>

#include <thread>

#include <sodium/core.h>

#ifdef WITH_OPENSSL

#include <openssl/crypto.h>
struct CRYPTO_dynlock_value
{
    pthread_mutex_t mutex;
};

static pthread_mutex_t* mutex_buf = nullptr;

/**
 * OpenSSL locking function.
 *
 * @param    mode    lock mode
 * @param    n        lock number
 * @param    file    source file name
 * @param    line    source file line number
 */
static void locking_function(int                                 mode,
                             int                                 n,
                             __attribute__((unused)) const char* file,
                             __attribute__((unused)) int         line)
{
    if ((mode & CRYPTO_LOCK) != 0) {
        pthread_mutex_lock(&mutex_buf[n]);
    } else {
        pthread_mutex_unlock(&mutex_buf[n]);
    }
}

/**
 * OpenSSL uniq id function.
 *
 * @return    thread id
 */
// NOLINTNEXTLINE(google-runtime-int)
static unsigned long id_function()
{
    std::thread::id tid = std::this_thread::get_id();

    return std::hash<std::thread::id>()(tid);
}

// No multithreaded test is performed, hence no lock is used.
// Disable the code coverage for the creation and destruction of OpenSSL locks
/* LCOV_EXCL_START */

/**
 * OpenSSL allocate and initialize dynamic crypto lock.
 *
 * @param    file    source file name
 * @param    line    source file line number
 */
static struct CRYPTO_dynlock_value* dyn_create_function(
    __attribute__((unused)) const char* file,
    __attribute__((unused)) int         line)
{
    struct CRYPTO_dynlock_value* value;

    value = reinterpret_cast<struct CRYPTO_dynlock_value*>(
        malloc(sizeof(struct CRYPTO_dynlock_value)));
    if (value == nullptr) {
        goto err;
    }
    pthread_mutex_init(&value->mutex, nullptr);

    return value;

err:
    return (nullptr);
}

/**
 * OpenSSL dynamic locking function.
 *
 * @param    mode    lock mode
 * @param    l        lock structure pointer
 * @param    file    source file name
 * @param    line    source file line number
 */
static void dyn_lock_function(int                                 mode,
                              struct CRYPTO_dynlock_value*        l,
                              __attribute__((unused)) const char* file,
                              __attribute__((unused)) int         line)
{
    if ((mode & CRYPTO_LOCK) != 0) {
        pthread_mutex_lock(&l->mutex);
    } else {
        pthread_mutex_unlock(&l->mutex);
    }
}

/**
 * OpenSSL destroy dynamic crypto lock.
 *
 * @param    l        lock structure pointer
 * @param    file    source file name
 * @param    line    source file line number
 */

static void dyn_destroy_function(struct CRYPTO_dynlock_value*        l,
                                 __attribute__((unused)) const char* file,
                                 __attribute__((unused)) int         line)
{
    pthread_mutex_destroy(&l->mutex);
    free(l);
}

/* LCOV_EXCL_STOP*/
#endif


namespace sse {

namespace crypto {

static relicxx::relicResourceHandle* g_relic_handle_;

static int init_locks()
{
#ifdef WITH_OPENSSL
    int i;

    /* static locks area */
    mutex_buf = static_cast<pthread_mutex_t*>(malloc(
        static_cast<size_t>(CRYPTO_num_locks()) * sizeof(pthread_mutex_t)));
    if (mutex_buf == nullptr) {
        /* LCOV_EXCL_START */
        return (-1);
        /* LCOV_EXCL_STOP */
    }
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&mutex_buf[i], nullptr);
    }
    /* static locks callbacks */
    CRYPTO_set_locking_callback(locking_function);
    CRYPTO_set_id_callback(id_function);
    /* dynamic locks callbacks */
    CRYPTO_set_dynlock_create_callback(&dyn_create_function);
    CRYPTO_set_dynlock_lock_callback(&dyn_lock_function);
    CRYPTO_set_dynlock_destroy_callback(&dyn_destroy_function);
#endif
    return 0;
}

static int kill_locks()
{
#ifdef WITH_OPENSSL

    int i;

    if (mutex_buf == nullptr) {
        /* LCOV_EXCL_START */
        return (0);
        /* LCOV_EXCL_STOP */
    }

    CRYPTO_set_dynlock_create_callback(nullptr);
    CRYPTO_set_dynlock_lock_callback(nullptr);
    CRYPTO_set_dynlock_destroy_callback(nullptr);

    CRYPTO_set_locking_callback(nullptr);
    CRYPTO_set_id_callback(nullptr);

    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_destroy(&mutex_buf[i]);
    }
    free(mutex_buf);
    mutex_buf = nullptr;
#endif
    return 0;
}

/* LCOV_EXCL_START */
[[noreturn]] static void sodium_misuse_handler()
{
    throw std::runtime_error("Sodium Misuse");
}
/* LCOV_EXCL_STOP */

void init_crypto_lib()
{
    init_locks();

    g_relic_handle_ = new relicxx::relicResourceHandle(true);

    if (sodium_init() < 0) {
        /* LCOV_EXCL_START */
        throw std::runtime_error("Unable to init libsodium");
        /* LCOV_EXCL_STOP */
    }
    sodium_set_misuse_handler(sodium_misuse_handler);

    Prp::compute_is_available();
}

void cleanup_crypto_lib()
{
    delete g_relic_handle_;
    g_relic_handle_ = nullptr;

    kill_locks();
}

// The next function is a clone of strstr with strong bounds guarantee,
// similarly to strncmp vs. strcmp
// Solution copied from https://stackoverflow.com/a/13451104
const uint8_t* strstrn_uint8(const uint8_t* str1,
                             const size_t   str1_len,
                             const uint8_t* str2,
                             const size_t   str2_len)
{
    if ((str2_len == 0)) {
        return str1;
    }
    if ((str1_len == 0)) {
        return nullptr;
    }

    size_t loc_str2 = 0;
    size_t loc_str1 = 0;
    for (loc_str1 = 0; loc_str1 - loc_str2 + str2_len <= str1_len; loc_str1++) {
        if (str1[loc_str1] == str2[loc_str2]) {
            loc_str2++;
            if (loc_str2 == str2_len) {
                return str1 + loc_str1 - loc_str2 + 1;
            }
        } else {
            loc_str1 -= loc_str2;
            loc_str2 = 0;
        }
    }
    return nullptr;
}

} // namespace crypto
} // namespace sse
