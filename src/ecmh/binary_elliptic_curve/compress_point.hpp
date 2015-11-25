#ifndef HEADER_GUARD_97e377881f24e41666cd630cc2e87576
#define HEADER_GUARD_97e377881f24e41666cd630cc2e87576

#include "./Point.hpp"
#include "ecmh/utility/assign_endian.hpp"
#include "ecmh/utility/is_byte.hpp"
#include <boost/range/algorithm/fill.hpp>

namespace jbms {
namespace binary_elliptic_curve {


template <class Curve, class Data, boost::endian::order order, JBMS_ENABLE_IF(is_byte_range<Data>)>
void compress_point(Curve const &curve, endian_wrapper<Data,order> result, LambdaAffinePoint<Curve> const &P) {
  result.ensure_size_equals(curve.field().num_bytes());

  assign(curve.field(), result, P.x());
  uint8_t &last_byte = result.data[order == boost::endian::order::big ? 0 : result.data.size() - 1];
  if (is_zero(curve.field(), P.x())) {
    // encode the (x=0,y=curve.sqrt_b()) point as x =0 with the extra bit set
    last_byte |= (uint8_t(1) << 7);
  } else {
    last_byte |= (uint8_t(get_bit(curve.field(), P.m(), 0)) << 7);
  }
}

template <class Curve, class Data, boost::endian::order order, JBMS_ENABLE_IF(is_byte_range<Data>)>
void compress_point(Curve const &curve, endian_wrapper<Data,order> result, LambdaProjectivePoint<Curve> const &P) {
  result.ensure_size_equals(curve.field().num_bytes());

  if (is_infinity(curve, P)) {
    // encode infinity as all 0
    boost::fill(result.data, uint8_t(0));
  } else {
    LambdaAffinePoint<Curve> P_affine;
    assign(curve, P_affine, P);
    compress_point(curve, result, P_affine);
  }
}

template <class Curve, class Data, boost::endian::order order, JBMS_ENABLE_IF(is_byte_range<Data>)>
void decompress_point(Curve const &curve, LambdaProjectivePoint<Curve> &P, endian_wrapper<Data,order> source) {

  assign(curve.field(), P.x(), source);

  uint8_t last_byte = source.data[order == boost::endian::order::big ? 0 : source.data.size() - 1];

  if (is_zero(curve.field(), P.x())) {
    if (last_byte >> 7) {
      // last_bit is 1, must be the (x = 0, y = sqrt(b)) point
      set_one(curve.field(), P.z());
      set_zero(curve.field(), P.m());
    } else {
      set_zero(curve.field(), P.z());
      set_one(curve.field(), P.m());
    }
  } else {
    valid_lambda_from_non_zero_x(curve, P.m(), P.x());
    set_bit(curve.field(), P.m(), 0, bool(last_byte >> 7));
    set_one(curve.field(), P.z());
  }
}


}
}

#endif /* HEADER GUARD */
