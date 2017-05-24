// This is derived from supercop/crypto_hash/blake2b/xmm

/*
   BLAKE2 reference source code package - optimized C implementations

   Written in 2012 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include "./blake2b-common.h"
#include "./blake2b.hpp"

namespace sse {
    namespace crypto {
        void hash::blake2b::hash(const unsigned char *in, size_t inlen, unsigned char *out) {
            blake2b_hash(in, inlen, out);
        }

    }
}
