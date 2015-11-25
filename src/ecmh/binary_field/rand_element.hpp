#ifndef HEADER_GUARD_8e132dcc661918ae32a9c92c2e7f80de
#define HEADER_GUARD_8e132dcc661918ae32a9c92c2e7f80de

#include "ecmh/binary_field/detail/field_operation_helpers.hpp"
#include "openssl/rand.hpp"
#include "ecmh/utility/assign_endian.hpp"
#include <vector>

namespace jbms {
namespace binary_field {

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
typename Field::Element pseudo_rand_element(Field const &F) {
  std::vector<uint8_t> buf(F.num_bytes());
  jbms::openssl::rand_pseudo_bytes(buf);
  typename Field::Element x;
  assign(F, x, jbms::little_endian(buf));
  return x;
}


template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
typename Field::Element rand_element(Field const &F) {
  std::vector<uint8_t> buf(F.num_bytes());
  jbms::openssl::rand_bytes(buf);
  typename Field::Element x;
  assign(F, x, jbms::little_endian(buf));
  return x;
}


}
}

#endif /* HEADER GUARD */
