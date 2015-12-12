#pragma once

#include <string.h>

namespace sse {
namespace crypto {
namespace hash {

struct blake2b {
  constexpr static size_t kDigestSize = 64;
  constexpr static size_t kBlockSize = 128;

  static void hash(const unsigned char *in, size_t inlen, unsigned char *out);
};

}
}
}
