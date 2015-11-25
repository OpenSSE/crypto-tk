#ifndef HEADER_GUARD_23c4d57589cf9984bc95d48d6218a34b
#define HEADER_GUARD_23c4d57589cf9984bc95d48d6218a34b

#include "detail/GF2.hpp"
#include "detail/field_operation_helpers.hpp"

namespace jbms {
namespace binary_field {

// Compute result = QS(h) using blinding to avoid leaking h.
// WARNING: The blinding is only valid in the case that trace(h) == 0.
template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
void solve_quadratic_blinded(Field const &F, typename Field::Element &result, typename Field::Element const &h) {
  using FE = typename Field::Element;
  FE y; // random element used for blinding QS operation
  assign_random(F, y);
  set_in_qs_image(F, y);

  // y^2 + y:      is uniformly random among elements with zero trace.
  // y^2 + y + h:  is also uniformly random among elements with zero trace, since trace(h) = 0.

  // We therefore leak no information from computing QS(z = y^2 + y + h).
  FE z; // = y^2 + y + h
  square(F, z, y);
  add(F, z, z, y);
  add(F, z, z, h);
  // Set m = QS(z) = QS(h) + y
  solve_quadratic(F, result, z);
  // Set m = QS(h).
  add(F, result, result, y);
}

}
}

#endif /* HEADER GUARD */
