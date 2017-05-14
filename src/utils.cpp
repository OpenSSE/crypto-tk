//
//  utils.cpp
//  libsse_crypto
//
//  Created by Raphael Bost on 06/04/2016.
//  Copyright © 2016 VSSE project. All rights reserved.
//

#include "utils.hpp"

#include <openssl/crypto.h>

#include <thread>

#include "ppke/relic_wrapper/relic_api.h"

struct CRYPTO_dynlock_value
{
    pthread_mutex_t mutex;
};

static pthread_mutex_t *mutex_buf = NULL;

/**
 * OpenSSL locking function.
 *
 * @param    mode    lock mode
 * @param    n        lock number
 * @param    file    source file name
 * @param    line    source file line number
 * @return    none
 */
static void locking_function(int mode, int n, const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
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
static unsigned long id_function(void)
{
    return ((unsigned long) pthread_self());
}

/**
 * OpenSSL allocate and initialize dynamic crypto lock.
 *
 * @param    file    source file name
 * @param    line    source file line number
 */
static struct CRYPTO_dynlock_value *dyn_create_function(const char *file, int line)
{
    struct CRYPTO_dynlock_value *value;
    
    value = (struct CRYPTO_dynlock_value *)
    malloc(sizeof(struct CRYPTO_dynlock_value));
    if (!value) {
        goto err;
    }
    pthread_mutex_init(&value->mutex, NULL);
    
    return value;
    
err:
    return (NULL);
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
static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l,
                              const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
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

static void dyn_destroy_function(struct CRYPTO_dynlock_value *l,
                                 const char *file, int line)
{
    pthread_mutex_destroy(&l->mutex);
    free(l);
}

namespace sse
{
    
    namespace crypto
    {
        
        static relicxx::relicResourceHandle *__relic_handle;

        static int init_locks(void)
        {
            int i;
            
            /* static locks area */
            mutex_buf = (pthread_mutex_t*)malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
            if (mutex_buf == NULL) {
                return (-1);
            }
            for (i = 0; i < CRYPTO_num_locks(); i++) {
                pthread_mutex_init(&mutex_buf[i], NULL);
            }
            /* static locks callbacks */
            CRYPTO_set_locking_callback(locking_function);
            CRYPTO_set_id_callback(id_function);
            /* dynamic locks callbacks */
            CRYPTO_set_dynlock_create_callback(&dyn_create_function);
            CRYPTO_set_dynlock_lock_callback(&dyn_lock_function);
            CRYPTO_set_dynlock_destroy_callback(&dyn_destroy_function);
            return 0;
        }
        
        static int kill_locks(void)
        {
            int i;
            
            if (mutex_buf == NULL) {
                return (0);
            }
            
            CRYPTO_set_dynlock_create_callback(NULL);
            CRYPTO_set_dynlock_lock_callback(NULL);
            CRYPTO_set_dynlock_destroy_callback(NULL);
            
            CRYPTO_set_locking_callback(NULL);
            CRYPTO_set_id_callback(NULL);
            
            for (i = 0; i < CRYPTO_num_locks(); i++) {
                pthread_mutex_destroy(&mutex_buf[i]); 
            } 
            free(mutex_buf); 
            mutex_buf = NULL; 
            return 0;
        }

        void init_crypto_lib()
        {
            init_locks();
            
            __relic_handle = new relicxx::relicResourceHandle(true);

        }
        void cleanup_crypto_lib()
        {
            delete  __relic_handle;
            __relic_handle = NULL;
            
            kill_locks();
        }
    }
}
