#pragma once

#include <string.h>

namespace sse {
namespace crypto {
namespace hash {

struct blake2s {
  constexpr static size_t kDigestSize = 32;
  constexpr static size_t kBlockSize = 64;

  static void hash(const unsigned char *in, size_t inlen, unsigned char *out);
};

}
}
}
