#pragma once

#include <string.h>

namespace sse {
namespace crypto {
namespace hash {

struct blake2b {
  constexpr static size_t digest_bytes = 64;
  constexpr static size_t block_bytes = 128;

  static void hash(const unsigned char *in, size_t inlen, unsigned char *out);
};

}
}
}
