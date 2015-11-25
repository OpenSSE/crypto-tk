#ifndef HEADER_GUARD_87eb0c2ff4b7f8bb3256c49f7b619c41
#define HEADER_GUARD_87eb0c2ff4b7f8bb3256c49f7b619c41

#include "ecmh/array_view/array_view.hpp"

namespace jbms {
namespace hash {

// Stores num_digests * Hash::digest_bytes starting at result pointer
template <class Hash>
inline void hash_expand(Hash const &H, uint8_t *result, size_t num_digests, array_view<void const> data) {
  if (num_digests == 1) {
    // Just a single call to the hash function is required
    H.hash(result, data.data(), data.size());
  } else {
    if (data.size() >= Hash::block_bytes - 1) {
      // Compute a hash of the hash, rather than a hash directly

      // We need to ensure that we can't end up with a collision between this case and the case that data.size() <
      // Hash::block_bytes.  We do that by ensuring in this case that the first byte is 1, and 0 in the other case.

      uint8_t temp[Hash::digest_bytes + 2];
      temp[0] = 1;

      // We will need at least two calls to the compression function
      // Even if we require just two digests of output, it is still more efficient to compute a hash of the hash
      H.hash(temp+2, data.data(), data.size());

      for (size_t i = 0; i < num_digests; ++i) {
        temp[1] = (uint8_t)i;
        H.hash(result + Hash::digest_bytes * i, temp, Hash::digest_bytes + 2);
      }
    } else {
      // Compute multiple hashes of the input
      uint8_t temp[Hash::block_bytes];
      size_t data_size = data.size();
      temp[0] = 0;
      memcpy(temp + 2, data.data(), data_size);

      for (size_t i = 0; i < num_digests; ++i) {
        temp[1] = (uint8_t)i;
        H.hash(result + Hash::digest_bytes * i, temp, data_size + 2);
      }
    }
  }
}

}
}

#endif /* HEADER GUARD */
