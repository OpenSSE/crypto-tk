#ifndef HEADER_GUARD_3946c4c6118e979eedf899cd1d704d41
#define HEADER_GUARD_3946c4c6118e979eedf899cd1d704d41

#include "./detail/field_operation_helpers.hpp"

namespace jbms {
namespace binary_field {

// Blinded implementation of invert.
template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
void invert_blinded(Field const &F, typename Field::Element &result, typename Field::Element const &x) {
  using FE = typename Field::Element;
  FE y; // blinding value
  do {
    assign_random(F, y);
  } while (is_zero(F, y));

  FE z; // = y * x
  // z is a uniformly random invertible element of F
  multiply(F, z, y, x);

  // Assign: result = z^{-1} = y^{-1} x^{-1}
  invert(F, result, z);
  // result = x^{-1} = z^{-1} * y.
  multiply(F, result, result, y);
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
typename Field::Element invert_blinded(Field const &F, typename Field::Element const &x) {
  typename Field::Element result;
  invert_blinded(F, result, x);
  return result;
}

}
}

#endif /* HEADER GUARD */
