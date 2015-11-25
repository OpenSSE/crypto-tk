#ifndef HEADER_GUARD_7d7e3042370a4280ce6d6341ebba157a
#define HEADER_GUARD_7d7e3042370a4280ce6d6341ebba157a

#include "./polynomial_base.hpp"
#include "./polynomial_multiply.hpp"
#include "./field_operation_helpers.hpp"
#include "ecmh/utility/assign_endian.hpp"
#include "ecmh/utility/is_byte.hpp"

namespace jbms {
namespace binary_field {

// Parameterized by the irreducible polynomial coefficients, excluding 0
template <size_t Degree, size_t... Coeffs>
struct GF2;

template <size_t Degree, size_t... Coeffs>
struct is_field<GF2<Degree, Coeffs...>> : std::true_type {};

template <size_t Degree, size_t... Coeffs>
struct GF2 {
  using Element = BinaryPolynomial<Degree>;
  using DoubleElement = BinaryPolynomial<Degree * 2>;
  constexpr static size_t degree() { return Degree; }
  constexpr static size_t num_bytes() { return Element::num_bytes; }
  using Modulus_seq = std::integer_sequence<size_t, Degree, Coeffs..., 0>;
  static constexpr std::array<size_t, sizeof...(Coeffs) + 2> modulus_arr = { { Degree, Coeffs..., 0 } };

#define DEFINE_GF2_OPS(ElementT)                                                                             \
  friend void assign(GF2 const &F, ElementT &x, bool value) { assign(x, value); }                            \
  friend void set_zero(GF2 const &F, ElementT &x) { set_zero(x); }                                           \
  friend bool is_zero(GF2 const &F, ElementT const &x) { return is_zero(x); }                                \
  friend void set_one(GF2 const &F, ElementT &x) { set_one(x); }                                             \
  friend bool is_one(GF2 const &F, ElementT const &x) { return is_one(x); }                                  \
  friend bool equal(GF2 const &F, ElementT const &a, ElementT const &b) { return (a == b); }                 \
  friend void add(GF2 const &F, ElementT &x, ElementT const &a, ElementT const &b) {                         \
    x = a;                                                                                                   \
    x += b;                                                                                                  \
  }                                                                                                          \
  friend std::string to_hex(GF2 const &F, ElementT const &a) { return to_hex(a); }                           \
  template <class Range>                                                                                     \
  friend void assign_from_hex(GF2 const &F, ElementT &a, Range const &range) {                               \
    assign_from_hex(a, range);                                                                               \
  }                                                                                                          \
  friend std::string to_bin(GF2 const &F, ElementT const &a) { return to_bin(a); }                           \
  template <class Data, boost::endian::order order, JBMS_ENABLE_IF(is_byte_range<Data>)>                     \
  friend void assign(GF2 const &F, ElementT &a, endian_wrapper<Data, order> x) {                             \
    a = x.operator ElementT();                                                                               \
  }                                                                                                          \
  template <class Data, boost::endian::order order, JBMS_ENABLE_IF(is_byte_range<Data>)>                     \
  friend void assign(GF2 const &F, endian_wrapper<Data, order> x, ElementT const &a) {                       \
    x = a;                                                                                                   \
  }                                                                                                          \
  friend bool get_bit(GF2 const &F, ElementT const &x, size_t i) { return x.get_bit(i); }                    \
  friend void set_bit(GF2 const &F, ElementT &x, size_t i, bool value) { x.set_bit(i, value); }              \
  friend bool is_zero_constant_time(GF2 const &F, ElementT const &a) { return is_zero_constant_time(a); }    \
  friend ElementT select_constant_time(GF2 const &F, ElementT const &a, ElementT const &b, bool condition) { \
    return select_constant_time(a, b, condition);                                                            \
  }                                                                                                          \
  friend void assign_random(GF2 const &F, ElementT &x) { assign_random(x); }                                 \
  /**/
  DEFINE_GF2_OPS(Element)
  DEFINE_GF2_OPS(DoubleElement)
#undef DEFINE_GF2_OPS

  friend bool get_bit(GF2 const &F, Zero const &, size_t i) { return false; }
  friend bool get_bit(GF2 const &F, One const &, size_t i) { return i == 0; }

  friend void multiply_no_reduce(GF2 const &F, DoubleElement &x, Element const &a, Element const &b) { x = a * b; }
  friend void square_no_reduce(GF2 const &F, DoubleElement &x, Element const &a) { x = square(a); }

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(class = void),
                                   /*condition*/((Degree % 2) == 1 && ((Degree - 1) / 2 + 1) % 2 == 1),
                                   /*out-arg condition*/ true,
                                   /*prefix*/ friend,
                                   half_trace,
                                   GF2,
                                   F,
                                   One,
                                   result,
                                   (One const &),
  { set_one(F, result); });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(class = void),
                                   /*condition*/((Degree % 2) == 1 && ((Degree - 1) / 2 + 1) % 2 == 0),
                                   /*out-arg condition*/ true,
                                   /*prefix*/ friend,
                                   half_trace,
                                   GF2,
                                   F,
                                   Zero,
                                   result,
                                   (One const &),
  { set_zero(F, result); });

  // solve_quadratic forwards to half_trace if degree is odd
  // Need to exclude Zero to avoid ambiguity
  JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(class E),
                                   /*condition*/((Degree % 2) == 1 && are_field_elements<GF2, E>::value &&
                                                 !std::is_same<E, Zero>::value),
                                   /*out-arg condition*/ true,
                                   /*prefix*/ friend,
                                   solve_quadratic,
                                   GF2,
                                   F,
                                   decltype(half_trace(std::declval<GF2 const &>(), std::declval<E const &>())),
                                   result,
                                   (E const &a),
  { half_trace(F, result, a); });

  template <JBMS_ENABLE_IF_C((Degree % 2) == 1)>
  friend void set_in_qs_image(GF2 const &F, Element &x) {
    set_trace_zero(F, x);
  }
};

}
}

#endif /* HEADER GUARD */
