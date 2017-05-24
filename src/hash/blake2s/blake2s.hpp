//
//  blake2s-common.h
//  libsse_crypto
//
//  Created by Raphael Bost on 24/05/2017.
//  Copyright © 2017 VSSE project. All rights reserved.
//

#pragma once

#include "./blake2s-common.h"

#include <string.h>

namespace sse {
namespace crypto {
namespace hash {

struct blake2s {
  constexpr static size_t kDigestSize = 32;
  constexpr static size_t kBlockSize = 64;

  static inline void hash(const unsigned char *in, size_t inlen, unsigned char *out)
    {
        blake2s_hash(in,inlen,out);
    }
};

}
}
}
