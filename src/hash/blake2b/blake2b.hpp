#pragma once

#include "./blake2b-common.h"

#include <string.h>

namespace sse {
namespace crypto {
namespace hash {

struct blake2b {
  constexpr static size_t kDigestSize = 64;
  constexpr static size_t kBlockSize = 128;

  static inline void hash(const unsigned char *in, size_t inlen, unsigned char *out)
    {
        blake2b_hash(in, inlen, out);
    }
};

}
}
}
