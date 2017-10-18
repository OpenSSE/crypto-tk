#ifndef HEADER_GUARD_8f16e9749df779894967c10e186fec09
#define HEADER_GUARD_8f16e9749df779894967c10e186fec09

#include "./detail/field_operation_helpers.hpp"
#include "ecmh/array_view/array_view.hpp"
#include "ecmh/utility/division.hpp"
#include "ecmh/hash/hash_expand.hpp"

namespace jbms {
namespace binary_field {

template <class Field, class Hash, JBMS_ENABLE_IF(is_field<Field>)>
void assign_hash(Field const &F, Hash const &H, typename Field::Element &result, jbms::array_view<void const> data) {
  // We assume this below
  static_assert(Hash::block_bytes > Hash::digest_bytes + 1,"");

  const size_t num_digests = div_ceil(F.num_bytes(), Hash::digest_bytes);
  
  //  alloc on the stack instead of uint8_t buf[num_digests * Hash::digest_bytes]
  uint8_t *buf = (uint8_t *)alloca(sizeof(uint8_t)*num_digests * Hash::digest_bytes);

  hash::hash_expand(H, buf, num_digests, data);
  assign(F, result, jbms::little_endian(jbms::array_view<uint8_t>(buf, F.num_bytes())));
}

}
}

#endif /* HEADER GUARD */
