#ifndef HEADER_GUARD_e190f808b84ae868a490bb360cf25280
#define HEADER_GUARD_e190f808b84ae868a490bb360cf25280

#include "./detail/field_operation_helpers.hpp"

namespace jbms {
namespace binary_field {

// Computes Tr(a) = \sum_{i=0}^{m-1} a^{2^i}
template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
bool generic_trace(Field const &F, typename Field::Element const &a) {
  int m = F.degree();
  auto cur_power = a;
  auto cur_sum = zero(F);

  for (int i = 0; i < m; ++i) {
    add(F, cur_sum, cur_sum, cur_power);
    square(F, cur_power, cur_power);
  }

  if (is_zero(F, cur_sum))
    return false;
  if (is_one(F, cur_sum))
    return true;
  throw std::logic_error("trace result should be 0 or 1");
}


}
}

#endif /* HEADER GUARD */
