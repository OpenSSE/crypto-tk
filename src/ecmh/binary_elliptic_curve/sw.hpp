#ifndef HEADER_GUARD_f2fe91f83c8b93ec64c5a3ff9101ce21
#define HEADER_GUARD_f2fe91f83c8b93ec64c5a3ff9101ce21

/**
 * Implements the characteristic 2 Shallue-van de Woestijne [1] encoding function, using an optimized method [2] that saves field inversions.
 *
 * [1] Shallue, Andrew, and Christiaan E. van de Woestijne. "Construction of rational points on elliptic curves over finite fields." Algorithmic number theory. Springer Berlin Heidelberg, 2006. 510-524.
 *
 * [2] Aranha, D. F., Fouque, P. A., Qian, C., Tibouchi, M., & Zapalowicz, J. C. Binary Elligator Squared.
 *
 **/

#include <array>
#include "./Point.hpp"
#include "ecmh/binary_field/detail/GF2.hpp"
#include "ecmh/binary_field/QuadraticExtension.hpp"
#include "ecmh/binary_field/batch_invert.hpp"
#include <boost/function_output_iterator.hpp>
#include <boost/range/algorithm/transform.hpp>

namespace jbms {
namespace binary_elliptic_curve {
namespace sw {

/**
 * Returns: t * (t + 1) * (t*t + t + 1) != 0
 * Equivalently:  t + t^4 != 0
 **/
template <class Field>
inline bool is_valid_t_parameter(Field const &F, typename Field::Element const &t) {
  return !is_zero(add(F, t, jbms::binary_field::multi_square<2>(F, t)));
}

template <size_t Degree, size_t... Coeffs>
inline void set_to_valid_t_parameter(jbms::binary_field::GF2<Degree,Coeffs...> const &F,
                                     jbms::binary_field::BinaryPolynomial<Degree> &t) {
  static_assert(Degree > 4, "degree must be greater than 4");
  // z + z^4 != 0 if Degree > 4
  set_zero(t);
  t.set_bit(1);
}

template <size_t BaseDegree, size_t... BaseCoeffs>
inline void
set_to_valid_t_parameter(jbms::binary_field::QuadraticExtension<jbms::binary_field::GF2<BaseDegree, BaseCoeffs...>> const &F,
                         std::array<jbms::binary_field::BinaryPolynomial<BaseDegree>, 2> &t) {
  set_zero(t[1]);
  set_to_valid_t_parameter(F.base_field(), t[0]);
}

template <class Field,
          decltype(set_to_valid_t_parameter(std::declval<Field const &>(), std::declval<typename Field::Element &>())) * = nullptr>
inline typename Field::Element get_valid_t_parameter(Field const &field) {
  typename Field::Element t;
  set_to_valid_t_parameter(field, t);
  return t;
}

template <class Curve>
struct Encoder {
  using Field = typename Curve::Field;
  using FE = typename Field::Element;

  // Precomputed encoding parameters derived from a fixed t
  std::array<FE,3> derived_t;
  std::array<FE,3> derived_t_inv;

  Encoder() = default;

  /**
   * Initializes the encoder with the specified value of t.
   *
   * Precondition:  t * (t + 1) * (t*t + t + 1) != 0
   **/
  explicit Encoder(Curve const &curve, FE const &t) {
    Field const &F = curve.field();

    FE tsqr; // tsqr = t * t
    square(F, tsqr, t);

    FE t_plus_1; // t_1 = t + 1
    set_one(F, t_plus_1);
    add(F, t_plus_1, t_plus_1, t);

    FE tsqr_plus_t_plus_1; // t2_t_1 = t^2 + t + 1
    add(F, tsqr_plus_t_plus_1, tsqr, t_plus_1);

    FE inv_tsqr_plus_t_plus_1; // = 1 / (1 + t + t^2)
    invert(F, inv_tsqr_plus_t_plus_1, tsqr_plus_t_plus_1);

    // t[0] = t / (1 + t + t^2)
    multiply(F, derived_t[0], t, inv_tsqr_plus_t_plus_1);

    // t[1] = (1 + t) / (1 + t + t^2)
    multiply(F, derived_t[1], t_plus_1, inv_tsqr_plus_t_plus_1);

    // t[2] = t * (1 + t) / (1 + t + t^2)
    multiply(F, derived_t[2], derived_t[1], t);

    for (int i = 0; i < 3; ++i)
      invert(F, derived_t_inv[i], derived_t[i]);
  }

  explicit Encoder(Curve const &curve)
    : Encoder(curve, get_valid_t_parameter(curve.field()))
  {}
};


template <class Curve>
void map_c_and_c_inv(Curve const &curve,
                     Encoder<Curve> const &encoder,
                     LambdaAffinePoint<Curve> &result,
                     typename Curve::Field::Element const &w,
                     typename Curve::Field::Element const &c,
                     typename Curve::Field::Element const &c_inv) {
  using Field = typename Curve::Field;
  using FE = typename Field::Element;

  auto &&F = curve.field();

  FE x_inv, h;
  for (int j = 0; j < 3; ++j) {
    multiply(F, result.x(), encoder.derived_t[j], c);
    multiply(F, x_inv, encoder.derived_t_inv[j], c_inv);
    square(F, h, x_inv);
    multiply(F, h, h, curve.b());
    add(F, h, h, result.x());

    add(F, h, h, curve.a());

    if (trace(F, h) == false) {
      solve_quadratic(F, result.m(), h);
      add(F, result.m(), result.m(), result.x());

      // add 1 iff the 0th bit of w is 1
      // c does not depend on this bit
      add(F, result.m(), convert(F, get_bit(F, w, 0)));
      return;
    }
  }

  throw std::logic_error("SW mapping failed");
}

template <class Curve>
void map(Curve const &curve,
         Encoder<Curve> const &encoder,
         LambdaAffinePoint<Curve> &result,
         typename Curve::Field::Element const &w) {

  using Field = typename Curve::Field;
  using FE = typename Field::Element;

  auto &&F = curve.field();

  FE c; // = w^2 + w + a
  square(F, c, w);
  add(F, c, c, w);
  add(F, c, c, curve.a());

  if (is_zero(F, c)) { // Can only happen if Tr(curve.a()) == 0
    set_non_lambda_point(curve, result);
    return;
  }

  map_c_and_c_inv(curve, encoder, result, w, c, invert(F, c));
}

template <class Curve,
          class OutputIterator,
          class InputRange,
          JBMS_ENABLE_IF_C(std::is_same<typename Curve::Field::Element,
                                        typename boost::range_value<std::remove_reference_t<InputRange>>::type>::value)>
void batch_map(Curve const &curve, Encoder<Curve> const &encoder, OutputIterator output_it, InputRange const &w_range) {

  using Field = typename Curve::Field;
  using FE = typename Field::Element;

  auto &&F = curve.field();

  size_t batch_size = boost::size(w_range);

//  // variable length array
//  FE c_arr[batch_size];
//  FE w_arr[batch_size];
//  bool zero_flag[batch_size];

  //  alloc on the stack instead
  FE *c_arr = (FE *)alloca(sizeof(FE)*batch_size);
  FE *w_arr = (FE *)alloca(sizeof(FE)*batch_size);
  bool *zero_flag = (bool *)alloca(sizeof(bool)*batch_size);

    
  auto w_it = boost::begin(w_range);
  for (size_t i = 0; i < batch_size; ++i, ++w_it) {
    auto const &w = w_arr[i] = *w_it;
    FE c; // = w^2 + w + a
    square(F, c, w);
    add(F, c, c, w);
    add(F, c, c, curve.a());
    if (is_zero(F,c)) {
      set_one(F,c_arr[i]);
      zero_flag[i] = true;
    } else {
      zero_flag[i] = false;
      c_arr[i] = c;
    }
  }

  size_t i = 0;
  auto process_output = [&, zero_flag = &zero_flag[0], w_arr = &w_arr[0], c_arr = &c_arr[0] ](FE const & c_inv) {
    LambdaAffinePoint<Curve> result;
    if (zero_flag[i]) {
      set_non_lambda_point(curve, result);
    } else {
      map_c_and_c_inv(curve, encoder, result, w_arr[i], c_arr[i], c_inv);
    }
    ++i;
    *output_it = result;
    ++output_it;
  };
  batch_invert(F, boost::make_function_output_iterator(process_output), jbms::make_view(c_arr, batch_size));
}


} // namespace jbms::binary_elliptic_curve::sw
}
}

#endif /* HEADER GUARD */
