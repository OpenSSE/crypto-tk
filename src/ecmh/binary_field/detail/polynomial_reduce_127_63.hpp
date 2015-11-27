#ifndef HEADER_GUARD_b140740c3cfc17f4d3c81603e3cc7b62
#define HEADER_GUARD_b140740c3cfc17f4d3c81603e3cc7b62

#include "./polynomial_base.hpp"
#include "./limb_ops.hpp"
#include "./GF2.hpp"
#include "ecmh/array_view/array_view.hpp"

namespace jbms {
namespace binary_field {

namespace detail {

inline void reduce_after_multiply(GF2<127,63> const &F, BinaryPolynomial<127> &z, BinaryPolynomial<127 * 2> const &r) {
  limb_t t0, m0 = r.limbs[0], m1 = r.limbs[1];
  t0 = ALIGNR<8>(m1, m0);
  t0 = XOR(t0, m1);
  m1 = SHL(m1, 1);
  m0 = XOR(m0, m1);
  m1 = UNPACKHI64(m1, t0);
  m0 = XOR(m0, m1);
  t0 = SHR(t0, 63);
  m0 = XOR(m0, t0);
  m1 = UNPACKLO64(t0, t0);
  m0 = XOR(m0, SHL(m1, 63));
  z.limbs[0] = m0;
}

inline void reduce_after_square(GF2<127,63> const &F, BinaryPolynomial<127> &z, BinaryPolynomial<127 * 2> const &r) {
  limb_t t0, m0 = r.limbs[0], m1 = r.limbs[1];
  t0 = ALIGNR<8>(m1, m0);
  t0 = XOR(t0, m1);
  m1 = SHL(m1, 1);
  m0 = XOR(m0, m1);
  t0 = UNPACKHI64(m1, t0);
  m0 = XOR(m0, t0);
  z.limbs[0] = m0;
}

}

using detail::reduce_after_multiply;
using detail::reduce_after_square;


}
}

#endif /* HEADER GUARD */
