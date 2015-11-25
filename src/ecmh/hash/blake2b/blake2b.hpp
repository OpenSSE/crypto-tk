#ifndef HEADER_GUARD_4b453a113d99002b2ff3e9c40fbd2aa7
#define HEADER_GUARD_4b453a113d99002b2ff3e9c40fbd2aa7

#include <string.h>

namespace jbms {
namespace hash {

struct blake2b {
  constexpr static size_t digest_bytes = 64;
  constexpr static size_t block_bytes = 128;

  static void hash(unsigned char *out, const unsigned char *in, size_t inlen);
};

}
}

#endif /* HEADER GUARD */
