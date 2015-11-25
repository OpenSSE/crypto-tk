#ifndef HEADER_GUARD_c91b0dae9f202fa6fe6d3721a44d15c2
#define HEADER_GUARD_c91b0dae9f202fa6fe6d3721a44d15c2

#include "./detail/field_operation_helpers.hpp"

namespace jbms {
namespace binary_field {

// Computes HTr(a) = \sum_{i=0}^{(m-1)/2} a^{2^(2i)}
template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
void generic_half_trace(Field const &F, typename Field::Element &result, typename Field::Element const &a) {
  int m = F.degree();
  if (m % 2 != 1)
    throw std::invalid_argument("generic_half_trace only valid for odd-degree binary fields");
  auto cur_power = a;
  set_zero(F, result);

  int max_val = (m-1)/2;

  for (int i = 0; i <= max_val; ++i) {
    add(F, result, result, cur_power);
    square(F, cur_power, cur_power);
    square(F, cur_power, cur_power);
  }
}


}
}


#endif /* HEADER GUARD */
