#ifndef HEADER_GUARD_1ba8be1df1478d3f0326ed53d6c5b05e
#define HEADER_GUARD_1ba8be1df1478d3f0326ed53d6c5b05e

#include <openssl/evp.h>
#include <assert.h>
#include "./error.hpp"

namespace jbms {
namespace openssl {

/**
 * \brief Wrapper around high-level symmetric cipher API
 **/
class evp_cipher_ctx {
  EVP_CIPHER_CTX ctx_;

public:
  operator EVP_CIPHER_CTX *() { return &ctx_; }
  EVP_CIPHER_CTX *get() { return &ctx_; }

  evp_cipher_ctx() { EVP_CIPHER_CTX_init(&ctx_); }


  /**
   * \brief Calls EVP_CipherUpdate
   *
   * \pre in.size() <= INT_MAX
   **/
#define JBMS_OPENSSL_EVP_CIPHER_DEFINE_UPDATE(NAME, IMPL_NAME) \
  size_t NAME ## _update(void *out, array_view<void const> in) { \
    int outl; \
    throw_last_error_if( \
        EVP_## IMPL_NAME ## Update(&ctx_, reinterpret_cast<unsigned char *>(out), &outl, in.data(), static_cast<int>(in.size())) == 0); \
    return static_cast<size_t>(outl); \
  } \
  size_t NAME ## _final(unsigned char *out) { \
    int outl; \
    throw_last_error_if(EVP_## IMPL_NAME ## Final_ex(&ctx_, out, &outl) == 0); \
    return static_cast<size_t>(outl); \
  } \
  /**/

  /**
   * \param enc  Specifies whether to perform encryption or decryption.  It should be set to 1 for encryption, 0 for decryption,
   *and -1 to leave the value unchanged from a previous call.
   **/
  void cipher_init(const EVP_CIPHER *type, ENGINE *impl, unsigned char *key, unsigned char *iv, int enc) {
    throw_last_error_if(EVP_CipherInit_ex(&ctx_, type, impl, key, iv, enc) == 0);
  }

  JBMS_OPENSSL_EVP_CIPHER_DEFINE_UPDATE(cipher, Cipher)

#define JBMS_OPENSSL_EVP_CIPHER_DEFINE_ENCRYPT(NAME, IMPL_NAME)                                   \
  void NAME##_init(const EVP_CIPHER *type, ENGINE *impl, unsigned char *key, unsigned char *iv) { \
    throw_last_error_if(EVP_##IMPL_NAME##Init_ex(&ctx_, type, impl, key, iv) == 0);               \
  }                                                                                               \
  JBMS_OPENSSL_EVP_CIPHER_DEFINE_UPDATE(NAME, IMPL_NAME)                                          \
      /**/

  JBMS_OPENSSL_EVP_CIPHER_DEFINE_ENCRYPT(encrypt, Encrypt)
  JBMS_OPENSSL_EVP_CIPHER_DEFINE_ENCRYPT(decrypt, Decrypt)


  ~evp_cipher_ctx() {
    int x = EVP_CIPHER_CTX_cleanup(&ctx_);
    (void)x;
    // This should never fail.
    assert(x == 1);
  }
};


} // namespace jbms::openssl
} // namespace jbms

#endif /* HEADER GUARD */
