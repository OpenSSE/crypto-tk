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
 * @return    none
 */
static void locking_function(int mode, int n, const char* file, int line)
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
    // NOLINTNEXTLINE(google-runtime-int)
    return static_cast<unsigned long>(pthread_self());
}

/**
 * OpenSSL allocate and initialize dynamic crypto lock.
 *
 * @param    file    source file name
 * @param    line    source file line number
 */
static struct CRYPTO_dynlock_value* dyn_create_function(const char* file,
                                                        int         line)
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
 * @return    none
 */
static void dyn_lock_function(int                          mode,
                              struct CRYPTO_dynlock_value* l,
                              const char*                  file,
                              int                          line)
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
 * @return    none
 */

static void dyn_destroy_function(struct CRYPTO_dynlock_value* l,
                                 const char*                  file,
                                 int                          line)
{
    pthread_mutex_destroy(&l->mutex);
    free(l);
}

#endif


namespace sse {

namespace crypto {

static relicxx::relicResourceHandle* __relic_handle;

static int init_locks()
{
#ifdef WITH_OPENSSL
    int i;

    /* static locks area */
    mutex_buf = (pthread_mutex_t*)malloc(CRYPTO_num_locks()
                                         * sizeof(pthread_mutex_t));
    if (mutex_buf == nullptr) {
        return (-1);
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
        return (0);
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

static void sodium_misuse_handler()
{
    throw std::runtime_error("Sodium Misuse");
}

void init_crypto_lib()
{
    init_locks();

    __relic_handle = new relicxx::relicResourceHandle(true);

    if (sodium_init() < 0) {
        throw std::runtime_error("Unable to init libsodium");
    }
    sodium_set_misuse_handler(sodium_misuse_handler);

    Prp::compute_is_available();
}

void cleanup_crypto_lib()
{
    delete __relic_handle;
    __relic_handle = nullptr;

    kill_locks();
}
} // namespace crypto
} // namespace sse
