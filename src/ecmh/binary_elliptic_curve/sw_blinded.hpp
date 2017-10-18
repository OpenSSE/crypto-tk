/**
 * Blinded implementation of the characteristic 2 Shallue-van de Woestijne encoding function.
 **/

#ifndef HEADER_GUARD_2af5fc8e42204453066d1fcdc117b5c3
#define HEADER_GUARD_2af5fc8e42204453066d1fcdc117b5c3

#include "./sw.hpp"
#include "ecmh/binary_field/solve_quadratic_blinded.hpp"

namespace jbms {
namespace binary_elliptic_curve {
namespace sw {

template <class Curve>
void map_c_and_c_inv_blinded(Curve const &curve,
                             Encoder<Curve> const &encoder,
                             LambdaAffinePoint<Curve> &result,
                             typename Curve::Field::Element const &w,
                             typename Curve::Field::Element const &c,
                             typename Curve::Field::Element const &c_inv) {
  using Field = typename Curve::Field;
  using FE = typename Field::Element;

  auto &&F = curve.field();

  FE x_inv, h;
  bool found = false;
  FE found_h;
  FE found_x;
  for (int j = 0; j < 3; ++j) {
    FE temp_x;

    multiply(F, temp_x, encoder.derived_t[j], c);
    multiply(F, x_inv, encoder.derived_t_inv[j], c_inv);
    square(F, h, x_inv);
    multiply(F, h, h, curve.b());
    add(F, h, h, temp_x);

    add(F, h, h, curve.a());

    bool trace_is_zero = trace(F, h) ^ 1;

    bool is_first_found = trace_is_zero & (found ^ 1);
    found_h = select_constant_time(F, h, found_h, is_first_found);
    found_x = select_constant_time(F, temp_x, found_x, is_first_found);
    found |= trace_is_zero;
  }

  // Compute m = QS(h) using blinding to avoid leaking h.
  solve_quadratic_blinded(F, result.m(), found_h);

  assign(F, result.x(), found_x);
  add(F, result.m(), result.m(), found_x);

  // add 1 iff the 0th bit of w is 1
  // c does not depend on this bit
  add(F, result.m(), convert(F, get_bit(F, w, 0)));
}

template <class Curve>
void map_blinded(Curve const &curve,
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

  bool is_c_zero = is_zero_constant_time(F, c);
  // If c is zero, we need to substitute a different value for blinding the inversion (otherwise we might leak the fact that it is zero).  We won't actually use the result in that case.
  c = select_constant_time(F, one(F), c, is_c_zero);

  // Compute the encoding (only used in the case that c was not zero originally).
  map_c_and_c_inv_blinded(curve, encoder, result, w, c, invert_blinded(F, c));

  // Handle the case that c was zero originally: the result will be the special point that cannot be represented using lambda coordinates.
  LambdaAffinePoint<Curve> non_lambda_pt;
  set_non_lambda_point(curve, non_lambda_pt);

  result.x() = select_constant_time(F, non_lambda_pt.x(), result.x(), is_c_zero);
  result.m() = select_constant_time(F, non_lambda_pt.m(), result.m(), is_c_zero);
}

template <bool blinded, class Curve>
void map(Curve const &curve,
         Encoder<Curve> const &encoder,
         LambdaAffinePoint<Curve> &result,
         typename Curve::Field::Element const &w) {
  if (blinded)
    map_blinded(curve, encoder, result, w);
  else
    map(curve, encoder, result, w);
}

template <class Curve,
          class OutputIterator,
          class InputRange,
          JBMS_ENABLE_IF_C(std::is_same<typename Curve::Field::Element,
                                        typename boost::range_value<std::remove_reference_t<InputRange>>::type>::value)>
void batch_map_blinded(Curve const &curve, Encoder<Curve> const &encoder, OutputIterator output_it, InputRange const &w_range) {

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
    bool is_zero_val = is_zero_constant_time(F, c);
    c_arr[i] = select_constant_time(F, one(F), c, is_zero_val);
    zero_flag[i] = is_zero_val;
  }

  size_t i = 0;

  LambdaAffinePoint<Curve> non_lambda_pt;
  set_non_lambda_point(curve, non_lambda_pt);

  auto process_output = [&, zero_flag = &zero_flag[0], w_arr = &w_arr[0], c_arr = &c_arr[0] ](FE const & c_inv) {

    LambdaAffinePoint<Curve> result;

    map_c_and_c_inv_blinded(curve, encoder, result, w_arr[i], c_arr[i], c_inv);

    bool is_c_zero = zero_flag[i];
    // Handle case that c == 0.
    result.x() = select_constant_time(F, non_lambda_pt.x(), result.x(), is_c_zero);
    result.m() = select_constant_time(F, non_lambda_pt.m(), result.m(), is_c_zero);

    ++i;
    *output_it = result;
    ++output_it;
  };
  batch_invert_blinded(F, boost::make_function_output_iterator(process_output), jbms::make_view(c_arr, batch_size));
}

template <bool blinded,
          class Curve,
          class OutputIterator,
          class InputRange,
          JBMS_ENABLE_IF_C(std::is_same<typename Curve::Field::Element,
                                        typename boost::range_value<std::remove_reference_t<InputRange>>::type>::value)>
void batch_map(Curve const &curve, Encoder<Curve> const &encoder, OutputIterator output_it, InputRange const &w_range) {
  if (blinded)
    batch_map_blinded(curve, encoder, output_it, w_range);
  else
    batch_map(curve, encoder, output_it, w_range);
}


} // namespace jbms::binary_elliptic_curve::sw
}
}

#endif /* HEADER GUARD */
