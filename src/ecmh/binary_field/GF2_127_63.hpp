#ifndef HEADER_GUARD_0CA609C3B78EBF3C9DDF6AF0597EB191
#define HEADER_GUARD_0CA609C3B78EBF3C9DDF6AF0597EB191
#include "ecmh/binary_field/detail/polynomial_base.hpp"
#include "ecmh/binary_field/detail/polynomial_reduce_127_63.hpp"
#include "ecmh/binary_field/detail/polynomial_multiply.hpp"
#include "ecmh/binary_field/detail/apply_linear_table_transform.hpp"
namespace jbms {
namespace binary_field {
using GF2_127_63 = GF2<127,63>;
} // namespace jbms::binary_field
} // namespace jbms
namespace jbms {
namespace binary_field {
namespace detail {
extern const BinaryPolynomial<127> (&half_trace_table_GF2_127_63)[16][256];
}
} // namespace jbms::binary_field
} // namespace jbms
namespace jbms {
namespace binary_field {
inline void half_trace(GF2<127,63> const &F, BinaryPolynomial<127> &result, BinaryPolynomial<127> const &x) {
  apply_linear_table_transform<8>(result, x, detail::half_trace_table_GF2_127_63);
}
} // namespace jbms::binary_field
} // namespace jbms
namespace jbms {
namespace binary_field {
inline bool trace(GF2<127,63> const &F, BinaryPolynomial<127> const &x) {
  return ((x.limbs[0][0] >> 0)) & 0x1;
}
inline void set_trace_zero(GF2<127,63> const &F, BinaryPolynomial<127> &x) {
x.limbs[0][0] ^= (word_t(trace(F, x)) << 0);
}
} // namespace jbms::binary_field
} // namespace jbms
namespace jbms {
namespace binary_field {
namespace detail {
extern const BinaryPolynomial<127> (&multi_square_table_11_GF2_127_63)[16][256];
}
} // namespace jbms::binary_field
} // namespace jbms
namespace jbms {
namespace binary_field {
template<>
inline void multi_square<11>(GF2<127,63> const &F, BinaryPolynomial<127> &result, BinaryPolynomial<127> const &x) {
  apply_linear_table_transform<8>(result, x, detail::multi_square_table_11_GF2_127_63);
}
} // namespace jbms::binary_field
} // namespace jbms
namespace jbms {
namespace binary_field {
namespace detail {
extern const BinaryPolynomial<127> (&multi_square_table_21_GF2_127_63)[16][256];
}
} // namespace jbms::binary_field
} // namespace jbms
namespace jbms {
namespace binary_field {
template<>
inline void multi_square<21>(GF2<127,63> const &F, BinaryPolynomial<127> &result, BinaryPolynomial<127> const &x) {
  apply_linear_table_transform<8>(result, x, detail::multi_square_table_21_GF2_127_63);
}
} // namespace jbms::binary_field
} // namespace jbms
namespace jbms {
namespace binary_field {
namespace detail {
extern const BinaryPolynomial<127> (&multi_square_table_63_GF2_127_63)[16][256];
}
} // namespace jbms::binary_field
} // namespace jbms
namespace jbms {
namespace binary_field {
template<>
inline void multi_square<63>(GF2<127,63> const &F, BinaryPolynomial<127> &result, BinaryPolynomial<127> const &x) {
  apply_linear_table_transform<8>(result, x, detail::multi_square_table_63_GF2_127_63);
}
} // namespace jbms::binary_field
} // namespace jbms


/**
 * Itoh-Tsujii invert implementation using polynomial basis
 * Addition chain: 2=(1 + 1) 4=(2 + 2) 6=(2 + 4) 10=(4 + 6) 11=(1 + 10) 21=(11 + 10) 42=(21 + 21) 63=(21 + 42) 126=(63 + 63)
 * Multi-square tables: 11 21 63
 **/

namespace jbms {
namespace binary_field {
namespace detail {
void invert_impl(BinaryPolynomial<127> &result, BinaryPolynomial<127> const &a1);
}
inline void invert(GF2<127,63> const &F, BinaryPolynomial<127> &result, BinaryPolynomial<127> const &x) {
  detail::invert_impl(result, x);
}
} // namespace jbms::binary_field
} // namespace jbms
#endif // HEADER GUARD
