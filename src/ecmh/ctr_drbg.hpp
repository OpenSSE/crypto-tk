// This implements a simple but very fast pseudo-random generator based on AES128-CTR that is intended to be cryptographically
// secure.
//
// It is based on CTR-DRBG.  Reseeding happens after 1 GB of output.  At each seeding, a fresh encryption key is obtained using
// OpenSSL's RNG and the counter is reset to 0.
//
// This uses OpenSSL's AES-NI implementation and therefore requires AES-NI.

#ifndef HEADER_GUARD_c6f1070eb29565a6dc02601730fcd444
#define HEADER_GUARD_c6f1070eb29565a6dc02601730fcd444

#include <openssl/aes.h>
#include <openssl/modes.h>
#include "ecmh/openssl/rand.hpp"
#include "ecmh/array_view/array_view.hpp"

namespace jbms {

extern "C" {
int aesni_set_encrypt_key(const unsigned char *userKey, int bits, AES_KEY *key);
int aesni_set_decrypt_key(const unsigned char *userKey, int bits, AES_KEY *key);

void aesni_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
void aesni_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);

void aesni_ecb_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, int enc);
void
aesni_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char *ivec, int enc);

void aesni_ctr32_encrypt_blocks(
    const unsigned char *in, unsigned char *out, size_t blocks, const AES_KEY *key, const unsigned char *ivec);
}

class ctr_drbg {
  AES_KEY key;
  std::array<unsigned char,1024> buffer;
  unsigned char iv[16];
  size_t buffer_pos;
  size_t stream_pos;
public:
  ctr_drbg() {
    // Fill buffer with 0 to make valgrind happy, even though the correctness doesn't depend on it.
    memset(buffer.data(), 0, buffer.size());
    reseed();
    fill();
  }

  void reseed() {
    std::array<unsigned char,16> key_data;
    jbms::openssl::rand_bytes(key_data);
    aesni_set_encrypt_key(key_data.data(), 128, &key);
    stream_pos = 0;
    memset(iv, 0, 16);
  }

  void fill() {
    // Reseed after 1 GiB of output.
    if (stream_pos >= 1024 * 1024 * 1024)
      reseed();
    buffer_pos = 0;
    unsigned int num = 0;
    unsigned char ecount_buf[16];
    // Note: For simplicity, the cipher stream is XORd into the existing value of buffer.  Since the cipher stream is random, even
    // if the existing contents of the buffer are known, the result is still random.
    CRYPTO_ctr128_encrypt_ctr32(
        buffer.data(), buffer.data(), buffer.size(), &key, iv, ecount_buf, &num, (ctr128_f)aesni_ctr32_encrypt_blocks);
    stream_pos += buffer.size();
  }

  void operator()(array_view<void> output) {
    while (!output.empty()) {
      size_t n = std::min(buffer.size() - buffer_pos, output.size());
      memcpy(output.data(), buffer.data() + buffer_pos, n);
      buffer_pos += n;
      output.advance_begin(n);
      if (buffer_pos == buffer.size())
        fill();
    }
  }
};

// Fills `out' with random bytes.
//
// Uses thread-local CTR-DRBG instance.
inline void ctr_drbg_generate(array_view<void> out) {
#warning thread_local is not supported by Mac OS libc implementation
  static /*thread_local*/ ctr_drbg rng;
  rng(out);
}

}

#endif /* HEADER GUARD */
