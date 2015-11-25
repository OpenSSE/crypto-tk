#ifndef HEADER_GUARD_dec4cce5e2484a9677fec3ed593f05ca
#define HEADER_GUARD_dec4cce5e2484a9677fec3ed593f05ca

#include <string.h>

namespace jbms {
namespace hash {

struct blake2s {
  constexpr static size_t digest_bytes = 32;
  constexpr static size_t block_bytes = 64;

  static void hash(unsigned char *out, const unsigned char *in, size_t inlen);
};

}
}

#endif /* HEADER GUARD */
