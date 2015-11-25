#ifndef HEADER_GUARD_85388145683fdf2c4f2c90852c45dd5f
#define HEADER_GUARD_85388145683fdf2c4f2c90852c45dd5f

#include <mutex>
#include <openssl/crypto.h>

namespace jbms {
namespace openssl {

/**
 * @brief Make OpenSSL safe to use from multiple threads
 *
 * OpenSSL is NOT thread safe by default.  To make it thread-safe, we install a locking implementation.
 *
 * This function can safely be called from multiple times and from multiple threads simultaneously; it simply does nothing if it
 * has already been called.  However, the underlying OpenSSL API that this uses is NOT thread safe.  Therefore, it is unsafe to
 * call this while other code may be directly invoking OpenSSL to set up locking.
 *
 * If CRYPTO_set_locking_callback has already been called, nothing is done.
 *
 * WARNING: If this function compiled into a shared library that is unloaded during program execution, then the lock handlers may be removed when it is unloaded.  If OpenSSL is still being used in the program, this is unsafe.  Unfortunately there is no good way to work around this.
 **/
inline void enable_locking() {

  // This is a struct because we need a destructor.  However, it is a singleton.
  struct lock_manager {
    // This array will be initialized only if we install our locking functions.
    static std::unique_ptr<std::mutex[]> mutexes;

    static void locking_function(int mode, int n, const char *file, int line) {
      if (mode & CRYPTO_LOCK)
        mutexes[n].lock();
      else
        mutexes[n].unlock();
    }

    static CRYPTO_dynlock_value *dyn_create_function(const char *file, int line) { return new CRYPTO_dynlock_value; }

    static void dyn_lock_function(int mode, CRYPTO_dynlock_value *l, const char *file, int line) {
      if (mode & CRYPTO_LOCK)
        l->mutex.lock();
      else
        l->mutex.unlock();
    }

    static void dyn_destroy_function(CRYPTO_dynlock_value *l, const char *file, int line) { delete l; }

    lock_manager() {
      if (!CRYPTO_get_locking_callback()) {
        mutexes.reset(new std::mutex[CRYPTO_num_locks()]);
        CRYPTO_set_locking_callback(&lock_manager::locking_function);
        CRYPTO_set_dynlock_create_callback(&lock_manager::dyn_create_function);
        CRYPTO_set_dynlock_lock_callback(&lock_manager::dyn_lock_function);
        CRYPTO_set_dynlock_destroy_callback(&lock_manager::dyn_destroy_function);
      }
    }

    ~lock_manager() {
      if (mutexes) {
        // locking was initialized

        if (CRYPTO_get_locking_callback() != &lock_manager::locking_function) {
          // Something else has changed the callbacks.
          // We had better leave them alone.
        } else {
          CRYPTO_set_dynlock_create_callback(NULL);
          CRYPTO_set_dynlock_lock_callback(NULL);
          CRYPTO_set_dynlock_destroy_callback(NULL);
          CRYPTO_set_locking_callback(NULL);
        }

        // Free mutexes
        mutexes.reset();
      }
    }
  };

  // C++11 guarantees thread-safe initialization of function static variables.
  // Additionally, we are guaranteed there is exactly one copy of this variable, even though this is defined in a header file.
  static detail::lock_manager lock_manager;
}


}
}


#endif /* HEADER GUARD */
