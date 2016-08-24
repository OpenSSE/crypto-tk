#ifndef HEADER_GUARD_95e5047c81d56cc546ecb7ad471b6d6e
#define HEADER_GUARD_95e5047c81d56cc546ecb7ad471b6d6e

#include "./detail/field_operation_helpers.hpp"
#include <boost/range/iterator_range.hpp>
#include "ecmh/array_view/array_view.hpp"
#include <array>

namespace jbms {
namespace binary_field {

/**
 * Quadratic extension of a base binary field modulo polynomial u^2 + u + 1
 *
 * This is irreducible in the base field iff the base field degree is odd.
 * Thus, QuadraticExtension may only be used with odd-degree base fields.
 *
 * Quadratic extension field elements are represented as a two-element std::array of base field elements.
 *
 * Additionally, base field elements can be used directly as elements of the extension field, and operations are more efficient.
 *
 * The special element QuadraticU equal to u and corresponding to {zero(base_field()),one(base_field())} can also be used.
 **/
template <class BaseField_>
struct QuadraticExtension;

// Represents an element (0, value)
template <class BaseElement>
struct QuadraticU {
  BaseElement value;
  QuadraticU() = default;
  explicit QuadraticU(BaseElement const &v) : value(v) {}
};

// Represents an element (value, value)
template <class BaseElement>
struct QuadraticUp1 {
  BaseElement value;
  QuadraticUp1() = default;
  explicit QuadraticUp1(BaseElement const &v) : value(v) {}
};


template <class BaseField>
struct is_field<QuadraticExtension<BaseField>> : is_field<BaseField> {};

template <class BaseField, class BaseElement>
struct is_field_element<QuadraticExtension<BaseField>, QuadraticU<BaseElement>> : is_field_element<BaseField,BaseElement> {};

template <class BaseField, class BaseElement>
struct is_special_field_element<QuadraticExtension<BaseField>, QuadraticU<BaseElement>> : is_field_element<BaseField,BaseElement> {};

template <class BaseField, class BaseElement>
struct is_field_element<QuadraticExtension<BaseField>, QuadraticUp1<BaseElement>> : is_field_element<BaseField,BaseElement> {};

template <class BaseField, class BaseElement>
struct is_special_field_element<QuadraticExtension<BaseField>, QuadraticUp1<BaseElement>> : is_field_element<BaseField,BaseElement> {};

template <class BaseField>
struct is_field_element<QuadraticExtension<BaseField>, typename BaseField::Element> : std::true_type {};

template <class BaseField>
struct is_special_field_element<QuadraticExtension<BaseField>, typename BaseField::Element> : std::true_type {};

template <class BaseField, class BaseElement>
struct is_field_element_convertible_to<QuadraticExtension<BaseField>, Zero, QuadraticU<BaseElement>> : std::true_type {};

template <class BaseField>
struct is_field_element_convertible_to<QuadraticExtension<BaseField>, Zero, typename BaseField::Element> : std::true_type {};

template <class BaseField>
struct is_field_element_convertible_to<QuadraticExtension<BaseField>, One, typename BaseField::Element> : std::true_type {};

template <class BaseField, class BaseElement>
struct is_field_element_convertible_to<QuadraticExtension<BaseField>, Zero, QuadraticUp1<BaseElement>> : std::true_type {};

template <class BaseField_>
struct QuadraticExtension {
  using BaseField = BaseField_;
  constexpr size_t degree() const { return base_field().degree() * 2; }
  constexpr size_t num_bytes() const { return base_field().num_bytes() * 2; }
  using Element = std::array<typename BaseField::Element, 2>;
  using DoubleElement = std::array<typename BaseField::DoubleElement, 2>;

  // Careful: this returns a reference
  template <size_t i>
  static constexpr auto const &get(Element const &a) { return a[i]; }

  // Careful: this returns a reference
  template <size_t i>
  static constexpr auto &get(Element &a) { return a[i]; }

  // Careful: this returns a reference
  template <size_t i, JBMS_DISABLE_IF(std::is_same<Element,DoubleElement>)>
  static constexpr auto const &get(DoubleElement const &a) { return a[i]; }

  // Careful: this returns a reference
  template <size_t i, JBMS_DISABLE_IF(std::is_same<Element,DoubleElement>)>
  static constexpr auto &get(DoubleElement &a) { return a[i]; }

  template <size_t i>
  static constexpr Zero get(Zero const &a) { return {}; }

  template <size_t i, JBMS_ENABLE_IF_C(i == 0)>
  static constexpr One get(One const &a) { return {}; }

  template <size_t i, JBMS_ENABLE_IF_C(i == 1)>
  static constexpr Zero get(One const &a) { return {}; }

  template <size_t i, class BaseElement, JBMS_ENABLE_IF_C(i == 0 && is_field_element<BaseField,BaseElement>::value)>
  static constexpr Zero get(QuadraticU<BaseElement> const &) { return {}; }

  // Careful: this returns a reference
  template <size_t i, class BaseElement, JBMS_ENABLE_IF_C(i == 1 && is_field_element<BaseField,BaseElement>::value)>
  static constexpr BaseElement const &get(QuadraticU<BaseElement> const &x) { return x.value; }

  // Careful: this returns a reference
  template <size_t i, class BaseElement, JBMS_ENABLE_IF_C(i == 1 && is_field_element<BaseField,BaseElement>::value)>
  static constexpr BaseElement &get(QuadraticU<BaseElement> &x) { return x.value; }

  // Careful: this returns a reference
  template <size_t i, class BaseElement, JBMS_ENABLE_IF(is_field_element<BaseField,BaseElement>)>
  static constexpr BaseElement const &get(QuadraticUp1<BaseElement> const &x) { return x.value; }

  template <size_t i, class BaseElement, JBMS_ENABLE_IF(is_field_element<BaseField,BaseElement>)>
  static constexpr BaseElement &get(QuadraticUp1<BaseElement> &x) { return x.value; }

  // Careful: this returns a reference
  template <size_t i, JBMS_ENABLE_IF_C(i == 0)>
  static constexpr typename BaseField::Element const &get(typename BaseField::Element const &a) { return a; }

  // Careful: this returns a reference
  template <size_t i, JBMS_ENABLE_IF_C(i == 0)>
  static constexpr typename BaseField::Element &get(typename BaseField::Element &a) { return a; }

  template <size_t i, JBMS_ENABLE_IF_C(i == 1)>
  static constexpr Zero get(typename BaseField::Element const &) { return {}; }

  static void copy_0_to_1(QuadraticExtension const &F, Element &a) { a[1] = a[0]; }

  static void copy_0_to_1(QuadraticExtension const &F, Zero const &a) {}

  template <class BaseElement>
  static void copy_0_to_1(QuadraticExtension const &F, QuadraticUp1<BaseElement> &a) {}

  template <class BaseElement>
  static void copy_0_to_1(QuadraticExtension const &F, QuadraticU<BaseElement> &a) {
    set_zero(F.base_field(), a.value);
  }

  template <class ElementT>
  using is_element = is_field_element<QuadraticExtension,ElementT>;

  template <class ElementT>
  using is_element_or_double = std::integral_constant<bool,
                                                      is_field_element<QuadraticExtension,ElementT>::value ||
                                                      std::is_same<ElementT,DoubleElement>::value>;

  template <class ElementT>
  using is_single_or_double = std::integral_constant<bool,
                                                     std::is_same<ElementT,Element>::value ||
                                                     std::is_same<ElementT,DoubleElement>::value>;

  QuadraticExtension() = default;
  QuadraticExtension(BaseField bf) : base_field_(bf) {}
  constexpr BaseField const &base_field() const { return base_field_; }

  template <class ElementT, JBMS_ENABLE_IF(is_element_or_double<ElementT>)>
  friend std::string to_hex(QuadraticExtension const &F, ElementT const &a) {
    return to_hex(F.base_field(), get<0>(a)) + ',' + to_hex(F.base_field(), get<1>(a));
  }

  template <class ElementT,
            class Range,
            JBMS_ENABLE_IF(is_single_or_double<ElementT>)>
  friend void assign_from_hex(QuadraticExtension const &F, ElementT &a, Range const &range) {
    auto split_it = std::find(range.begin(), range.end(), ',');
    if (split_it == range.end())
      throw std::invalid_argument("QuadraticExtension hex representation must contain a comma");
    assign_from_hex(F.base_field(), a[0], boost::make_iterator_range(range.begin(), split_it));
    ++split_it;
    assign_from_hex(F.base_field(), a[1], boost::make_iterator_range(split_it, range.end()));
  }

  template <class Data, boost::endian::order order>
  friend void assign(QuadraticExtension const &F, Element &a, endian_wrapper<Data, order> source) {
    if (source.data.size() != F.num_bytes())
      throw std::invalid_argument("invalid source length");

    auto source_view = jbms::make_view(source.data);
    size_t split_pos = F.base_field().num_bytes();
    assign(F.base_field(), a[0], make_endian_wrapper<order>(source_view.unchecked_slice_before(split_pos)));
    assign(F.base_field(), a[1], make_endian_wrapper<order>(source_view.unchecked_slice_after(split_pos)));
  }

  template <class Data, boost::endian::order order, class ElementT, JBMS_ENABLE_IF_C(is_field_element<QuadraticExtension,ElementT>::value)>
  friend void assign(QuadraticExtension const &F, endian_wrapper<Data, order> dest, ElementT const &a) {
    dest.ensure_size_equals(F.num_bytes());

    auto dest_view = jbms::make_view(dest.data);
    size_t split_pos = F.base_field().num_bytes();
    assign(F.base_field(), make_endian_wrapper<order>(dest_view.unchecked_slice_before(split_pos)), get<0>(a));
    assign(F.base_field(), make_endian_wrapper<order>(dest_view.unchecked_slice_after(split_pos)), get<1>(a));
  }

  template <class ElementT,
            JBMS_ENABLE_IF(is_single_or_double<ElementT>)>
  friend void set_zero(QuadraticExtension const &F, ElementT &x) {
    set_zero(F.base_field(), get<0>(x));
    set_zero(F.base_field(), get<1>(x));
  }

  template <class BaseElement, JBMS_ENABLE_IF(is_field_element<BaseField,BaseElement>)>
  friend void set_zero(QuadraticExtension const &F, QuadraticUp1<BaseElement> &a) {
    set_zero(F, a.value);
  }

  template <class ElementT,
            JBMS_ENABLE_IF(is_single_or_double<ElementT>)>
  friend void assign(QuadraticExtension const &F, ElementT &x, bool value) {
    assign(F.base_field(), get<0>(x), value);
    set_zero(F.base_field(), get<1>(x));
  }

  template <class ElementT,
            JBMS_ENABLE_IF(is_element_or_double<ElementT>)>
  friend void set_one(QuadraticExtension const &F, ElementT &x) {
    set_one(F.base_field(), get<0>(x));
    set_zero(F.base_field(), get<1>(x));
  }

  template <class ElementT, JBMS_ENABLE_IF(is_element_or_double<ElementT>)>
  friend bool is_zero(QuadraticExtension const &F, ElementT const &x) {
    return is_zero(F.base_field(), get<0>(x)) && is_zero(F.base_field(), get<1>(x));
  }

  template <class ElementT, JBMS_ENABLE_IF(is_element_or_double<ElementT>)>
  friend bool is_zero_constant_time(QuadraticExtension const &F, ElementT const &x)
  {
    return is_zero_constant_time(F.base_field(), get<0>(x) | get<1>(x));
  }

  template <class ElementT, JBMS_ENABLE_IF(is_element_or_double<ElementT>)>
  friend ElementT select_constant_time(QuadraticExtension const &F, ElementT const &a, ElementT const &b, bool condition) {
    return { { select_constant_time(F.base_field(), get<0>(a), get<0>(b), condition),
               select_constant_time(F.base_field(), get<1>(a), get<1>(b), condition) } };
  }

  template <class ElementT, JBMS_ENABLE_IF(is_element_or_double<ElementT>)>
  friend void assign_random(QuadraticExtension const &F, ElementT &x) {
    assign_random(F.base_field(), get<0>(x));
    assign_random(F.base_field(), get<1>(x));
  }

  template <class ElementT, JBMS_ENABLE_IF(is_element_or_double<ElementT>)>
  friend bool is_one(QuadraticExtension const &F, ElementT const &x) {
    return is_one(F.base_field(), get<0>(x)) && is_zero(F.base_field(), get<1>(x));
  }

  template <class BaseElement, JBMS_ENABLE_IF(is_field_element<BaseField,BaseElement>)>
  constexpr friend bool is_one(QuadraticExtension const &F, QuadraticUp1<BaseElement> const &a) { return false; }

  template <class ElementA, class ElementB,
            JBMS_ENABLE_IF_C((is_element_or_double<ElementA>::value ||
                              is_element_or_double<ElementB>::value) &&
                             !std::is_same<ElementA,Zero>::value && !std::is_same<ElementA,One>::value &&
                             !std::is_same<ElementB,Zero>::value && !std::is_same<ElementB,One>::value)>
  friend bool equal(QuadraticExtension<BaseField> const &F, ElementA const &a, ElementB const &b) {
    return equal(F.base_field(), get<0>(a), get<0>(b)) && equal(F.base_field(), get<1>(a), get<1>(b));
  }

  template <class ElementT,
            JBMS_ENABLE_IF_C(is_special_field_element<QuadraticExtension, ElementT>::value &&
                             !std::is_same<ElementT,One>::value &&
                             !std::is_same<ElementT,Zero>::value)>
  friend void assign(QuadraticExtension<BaseField> const &F, Element &result, ElementT const &a) {
    assign(F.base_field(), get<0>(result), get<0>(a));
    assign(F.base_field(), get<1>(result), get<1>(a));
  }

  template <class E1, class E2,
            JBMS_ENABLE_IF_C(is_element<E1>::value && is_element<E2>::value)>
  friend void add(QuadraticExtension<BaseField> const &F, Element &result, E1 const &a, E2 const &b) {
    add(F.base_field(), result[0], get<0>(a), get<0>(b));
    add(F.base_field(), result[1], get<1>(a), get<1>(b));
  }

  template <JBMS_DISABLE_IF(std::is_same<Element,DoubleElement>)>
  friend void add(QuadraticExtension<BaseField> const &F, DoubleElement &result, DoubleElement const &a, DoubleElement const &b) {
    add(F.base_field(), result[0], get<0>(a), get<0>(b));
    add(F.base_field(), result[1], get<1>(1), get<1>(1));
  }

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(class = void),
                                   /*condition*/ true,
                                   /*out-arg condition*/ true,
                                   /*prefix*/ friend,
                                   add,
                                   QuadraticExtension,
                                   F,
                                   typename BaseField::Element,
                                   result,
                                   (typename BaseField::Element const &a, typename BaseField::Element const &b),
  {
    add(F.base_field(), get<0>(result), a, b);
    set_zero(F.base_field(), get<1>(result));
  });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseE1, class BaseE2),
      /*condition*/(is_field_element<BaseField, BaseE1>::value &&is_field_element<BaseField, BaseE2>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      add,
      QuadraticExtension,
      F,
      QuadraticU<
          decltype(add(std::declval<BaseField const &>(), std::declval<BaseE1 const &>(), std::declval<BaseE2 const &>()))>,
      result,
      (QuadraticU<BaseE1> const &a, QuadraticU<BaseE2> const &b),
  {
        add(F.base_field(), get<1>(result), a.value, b.value);
        set_zero(F.base_field(), get<0>(result));
      });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseE1, class BaseE2),
      /*condition*/(is_field_element<BaseField, BaseE1>::value &&is_field_element<BaseField, BaseE2>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      add,
      QuadraticExtension,
      F,
      QuadraticUp1<
          decltype(add(std::declval<BaseField const &>(), std::declval<BaseE1 const &>(), std::declval<BaseE2 const &>()))>,
      result,
      (QuadraticUp1<BaseE1> const &a, QuadraticUp1<BaseE2> const &b),
  {
        add(F.base_field(), get<0>(result), a.value, b.value);
        copy_0_1(F, result);
      });

  friend void multiply_no_reduce(QuadraticExtension const &F, DoubleElement &result, Element const &a, Element const &b) {

    // multiply without reduction
    auto a0b0 = multiply_no_reduce(F.base_field(), a[0], b[0]);
    auto a1b1 = add(F.base_field(), multiply_no_reduce(F.base_field(), a[1], b[1]), a0b0);
    auto a2b2 = add(F.base_field(),
                    multiply_no_reduce(F.base_field(), add(F.base_field(), a[0], a[1]), add(F.base_field(), b[0], b[1])),
                    a0b0);
    result[0] = a1b1;
    result[1] = a2b2;
  }

  friend void reduce_after_multiply(QuadraticExtension const &F, Element &result, DoubleElement const &a) {
    reduce_after_multiply(F.base_field(), result[0], a[0]);
    reduce_after_multiply(F.base_field(), result[1], a[1]);
  }

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class = void),
      /*condition*/ true,
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      multiply,
      QuadraticExtension,
      F,
      typename BaseField::Element,
      result,
      (typename BaseField::Element const &a, typename BaseField::Element const &b),
      /*body*/
  {
        multiply(F.base_field(), get<0>(result), a, b);
        set_zero(F.base_field(), get<1>(result));
      });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class = void),
      /*condition*/true,
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      multiply,
      QuadraticExtension,
      F,
      Element,
      result,
      (typename BaseField::Element const &a, Element const &b),
      /*body*/
  {
    multiply(F.base_field(), get<0>(result), a, get<0>(b));
    multiply(F.base_field(), get<1>(result), a, get<1>(b));
      });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class = void),
      /*condition*/true,
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      multiply,
      QuadraticExtension,
      F,
      Element,
      result,
      (Element const &b, typename BaseField::Element const &a),
      /*body*/
  {
    multiply(F.base_field(), get<0>(result), a, get<0>(b));
    multiply(F.base_field(), get<1>(result), a, get<1>(b));
      });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseE1),
      /*condition*/(is_field_element<BaseField, BaseE1>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      multiply,
      QuadraticExtension,
      F,
      Element,
      result,
      (Element const &a, QuadraticU<BaseE1> const &b),
      /*body*/
  {
        auto a1b1 = multiply(F.base_field(), get<1>(a), get<1>(b));
        add(F.base_field(), result[1], a1b1, multiply(F.base_field(), get<0>(a), get<1>(b)));
        assign(F.base_field(), result[0], a1b1);
      });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseE1),
      /*condition*/(is_field_element<BaseField, BaseE1>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      multiply,
      QuadraticExtension,
      F,
      Element,
      result,
      (QuadraticU<BaseE1> const &b, Element const &a),
      /*body*/
  {
        auto a1b1 = multiply(F.base_field(), get<1>(a), get<1>(b));
        add(F.base_field(), result[1], a1b1, multiply(F.base_field(), get<0>(a), get<1>(b)));
        assign(F.base_field(), result[0], a1b1);
      });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseE1),
      /*condition*/(is_field_element<BaseField, BaseE1>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      multiply,
      QuadraticExtension,
      F,
      Element,
      result,
      (Element const &b, QuadraticUp1<BaseE1> const &a),
      /*body*/
  {
    auto ab1 = multiply(F.base_field(), a.value, get<1>(b));
    multiply(F.base_field(), result[1], a.value, get<0>(b));
    add(F.base_field(), result[0], result[1], ab1);
      });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseE1),
      /*condition*/(is_field_element<BaseField, BaseE1>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      multiply,
      QuadraticExtension,
      F,
      Element,
      result,
      (QuadraticUp1<BaseE1> const &a, Element const &b),
      /*body*/
  {
    auto ab1 = multiply(F.base_field(), a.value, get<1>(b));
    multiply(F.base_field(), result[1], a.value, get<0>(b));
    add(F.base_field(), result[0], result[1], ab1);
      });



  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseE1),
      /*condition*/(is_field_element<BaseField, BaseE1>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      multiply,
      QuadraticExtension,
      F,
      QuadraticU<decltype(multiply(std::declval<BaseField const &>(),
                                   std::declval<BaseE1 const &>(),
                                   std::declval<typename BaseField::Element const &>()))>,
      result,
      (typename BaseField::Element const &a, QuadraticU<BaseE1> const &b),
      /*body*/
  {
        multiply(F.base_field(), get<1>(result), a, b.value);
        set_zero(F.base_field(), get<0>(result));
      });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseE1),
      /*condition*/(is_field_element<BaseField, BaseE1>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      multiply,
      QuadraticExtension,
      F,
      QuadraticU<decltype(multiply(std::declval<BaseField const &>(),
                                   std::declval<BaseE1 const &>(),
                                   std::declval<typename BaseField::Element const &>()))>,
      result,
      (QuadraticU<BaseE1> const &b, typename BaseField::Element const &a),
      /*body*/
  {
        multiply(F.base_field(), get<1>(result), a, b.value);
        set_zero(F.base_field(), get<0>(result));
      });

    JBMS_BINARY_FIELD_DEFINE_OP_CASE(
                                     /*template params*/(class BaseE1, class BaseE2),
                                     /*condition*/(is_field_element<BaseField, BaseE1>::value && is_field_element<BaseField,BaseE2>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      multiply,
      QuadraticExtension,
      F,
      QuadraticUp1<decltype(multiply(std::declval<BaseField const &>(),
                                   std::declval<BaseE1 const &>(),
                                   std::declval<BaseE2 const &>()))>,
      result,
                                     (QuadraticU<BaseE1> const &a, QuadraticU<BaseE1> const &b),
      /*body*/
  {
        multiply(F.base_field(), get<0>(result), a.value, b.value);
        copy_0_1(F, result);
      });



  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseE1),
      /*condition*/(is_field_element<BaseField, BaseE1>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      multiply,
      QuadraticExtension,
      F,
      QuadraticUp1<decltype(multiply(std::declval<BaseField const &>(),
                                   std::declval<BaseE1 const &>(),
                                   std::declval<typename BaseField::Element const &>()))>,
      result,
      (typename BaseField::Element const &a, QuadraticUp1<BaseE1> const &b),
      /*body*/
  {
        multiply(F.base_field(), get<0>(result), a, b.value);
        copy_0_1(F, result);
      });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseE1),
      /*condition*/(is_field_element<BaseField, BaseE1>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      multiply,
      QuadraticExtension,
      F,
      QuadraticUp1<decltype(multiply(std::declval<BaseField const &>(),
                                     std::declval<BaseE1 const &>(),
                                     std::declval<typename BaseField::Element const &>()))>,
      result,
      (QuadraticUp1<BaseE1> const &b, typename BaseField::Element const &a),
      /*body*/
  {
        multiply(F.base_field(), get<0>(result), a, b.value);
        copy_0_1(F, result);
      });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseE1, class BaseE2),
      /*condition*/(is_field_element<BaseField, BaseE1>::value &&is_field_element<BaseField, BaseE2>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      multiply,
      QuadraticExtension,
      F,
      QuadraticU<
          decltype(multiply(std::declval<BaseField const &>(), std::declval<BaseE1 const &>(), std::declval<BaseE2 const &>()))>,
      result,
      (QuadraticUp1<BaseE1> const &a, QuadraticUp1<BaseE1> const &b),
      /*body*/
  {
        multiply(F.base_field(), get<1>(result), a.value, b.value);
        set_zero(F.base_field(), get<0>(result));
      });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseE1, class BaseE2),
      /*condition*/(is_field_element<BaseField, BaseE1>::value &&is_field_element<BaseField, BaseE2>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      multiply,
      QuadraticExtension,
      F,
      decltype(multiply(std::declval<BaseField const &>(), std::declval<BaseE1 const &>(), std::declval<BaseE2 const &>())),
      result,
      (QuadraticU<BaseE1> const &a, QuadraticUp1<BaseE1> const &b),
      /*body*/
  {
        multiply(F.base_field(), get<0>(result), a.value, b.value);
        set_zero(F.base_field(), get<1>(result));
      });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseE1, class BaseE2),
      /*condition*/(is_field_element<BaseField, BaseE1>::value &&is_field_element<BaseField, BaseE2>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      multiply,
      QuadraticExtension,
      F,
      decltype(multiply(std::declval<BaseField const &>(), std::declval<BaseE1 const &>(), std::declval<BaseE2 const &>())),
      result,
      (QuadraticUp1<BaseE1> const &a, QuadraticU<BaseE1> const &b),
      /*body*/
  {
        multiply(F.base_field(), get<0>(result), a.value, b.value);
        set_zero(F.base_field(), get<1>(result));
      });

  /**
   * square
   **/
  friend void square(QuadraticExtension const &F, Element &result, Element const &a) {
    // a^2 = (a[0] + get<1>(a) * u)^2 = (a[0]^2 + get<1>(a)^2 + get<1>(a)^2 * u)

    auto a0_sqr = square(F.base_field(), get<0>(a));
    auto a1_sqr = square(F.base_field(), get<1>(a));

    add(F.base_field(), result[0], a0_sqr, a1_sqr);
    assign(F.base_field(), result[1], a1_sqr);
  }

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class = void),
      /*condition*/ true,
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      square,
      QuadraticExtension,
      F,
      typename BaseField::Element,
      result,
      (typename BaseField::Element const &a),
      { square(F.base_field(), result, get<0>(a)); set_zero(F.base_field(), get<1>(a)); });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseElement),
      /*condition*/(is_field_element<BaseField, BaseElement>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      square,
      QuadraticExtension,
      F,
      QuadraticUp1<decltype(square(std::declval<BaseField const &>(), std::declval<BaseElement const &>()))>,
      result,
      (QuadraticU<BaseElement> const &a),
      { square(F.base_field(), get<0>(result), a.value); copy_0_1(F, result); });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseElement),
      /*condition*/(is_field_element<BaseField, BaseElement>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      square,
      QuadraticExtension,
      F,
      QuadraticU<decltype(square(std::declval<BaseField const &>(), std::declval<BaseElement const &>()))>,
      result,
      (QuadraticUp1<BaseElement> const &a),
  {
        square(F.base_field(), get<1>(result), a.value);
        set_zero(F, get<0>(result));
      });

  /**
   * invert
   **/
  template <class ElementT,
            JBMS_ENABLE_IF(is_element<ElementT>)>
  friend void invert(QuadraticExtension const &F, Element &result, ElementT const &a) {
    // result[0] = (a[0] + get<1>(a)) * t^{-1}
    // result[1] = get<1>(a) * t^{-1}
    // t = a[0] * get<1>(a) + a[0]^2 + get<1>(a)^2

    auto t = add(F.base_field(),
                 multiply(F.base_field(), get<0>(a), get<1>(a)),
                 add(F.base_field(), square(F.base_field(), get<0>(a)), square(F.base_field(), get<1>(a))));

    auto t_inv = invert(F.base_field(), t);

    result[0] = multiply(F.base_field(), add(F.base_field(), get<0>(a), get<1>(a)), t_inv);
    result[1] = multiply(F.base_field(), get<1>(a), t_inv);
  }


  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class = void),
      /*condition*/ true,
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      invert,
      QuadraticExtension,
      F,
      typename BaseField::Element,
      result,
      (typename BaseField::Element const &a),
      { invert(F.base_field(), get<0>(result), a); set_zero(F, get<1>(result)); });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseElement),
      /*condition*/ (is_field_element<BaseField,BaseElement>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      invert,
      QuadraticExtension,
      F,
      QuadraticUp1<BaseElement>,
      result,
      (QuadraticU<BaseElement> const &a),
      { invert(F.base_field(), get<0>(result), a.value); copy_0_1(F, result); });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseElement),
      /*condition*/ (is_field_element<BaseField,BaseElement>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      invert,
      QuadraticExtension,
      F,
      QuadraticU<BaseElement>,
      result,
      (QuadraticUp1<BaseElement> const &a),
      { invert(F.base_field(), get<1>(result), a.value); set_zero(F, get<0>(result)); });


  /**
   * solve_quadratic
   **/
  template <class ElementT,
            JBMS_ENABLE_IF(is_element<ElementT>)>
  friend void solve_quadratic(QuadraticExtension const &F, Element &result, ElementT const &a) {
    // We want:
    //   result^2 + result = a + Tr(a)
    // i.e.    result[0]^2 + result[1]^2 + result[0] = get<0>(a) + Tr(a) = get<0>(a) + Tr(get<1>(a))
    //    and  result[1]^2 + result[1] = get<1>(a)

    // x1 = half_trace(get<1>(a))
    // We have:   x1 + x1^2 = get<1>(a) + Tr(get<1>(a))

    // x0 = half_trace(x1 + get<1>(a) + get<0>(a))
    // We have:   x0 + x0^2 = x1 + get<1>(a) + get<0>(a) + Tr(get<1>(a) + get<0>(a))

    // result[0] = x0
    // result[1] = x1 + trace(x1 + get<1>(a) + get<0>(a))

    auto x1 = half_trace(F.base_field(), get<1>(a));
    auto sum = add(F.base_field(), add(F.base_field(), x1, get<1>(a)), get<0>(a));
    half_trace(F.base_field(), result[0], sum);
    add(F.base_field(), result[1], x1, convert(F.base_field(), trace(F.base_field(), sum)));
  }

  template <class E, JBMS_ENABLE_IF(is_element<E>)>
  friend bool trace(QuadraticExtension const &F, E const &a) {

    /**
       Tr_F(a_0 + u * a_1) = Tr_F(a_0) + Tr_F(u * a_1)

       Tr_F(a_0) = \sum_{i=0}^{2m-1} a_0^{2^i}
                 = \sum_{i=0}^{m-1} a_0^{2^i}   +   \sum_{i=m}^{2m-1} a_0^{2^i}
                 = \sum_{i=0}^{m-1} a_0^{2^i}   +   \sum_{i=0}^{m-1} a_0^{2^{m+i}}
                 = \sum_{i=0}^{m-1} a_0^{2^i}   +   \sum_{i=0}^{m-1} (a_0^{2^m})^{2^i}

                 = \sum_{i=0}^{m-1} a_0^{2^i}   +   \sum_{i=0}^{m-1} a_0^{2^i}
                 [ since a_0^{2^m} == a_0]

                 = 2 * \sum_{i=0}^{m-1} a_0^{2^i}
                 = 0

       Tr_F(u * a_1) = \sum_{i=0}^{2m-1} u^{2^i} a_1^{2^i}

         Note: u^2 = u + 1

         Note: (u + 1)^2 = u^2 + 2u + 1^2 = u^2 + 1 = u

         Therefore, for i even, u^{2^i} = u, and for i odd, u^{2^i} = u + 1

       Tr_F(u * a_1) = u * \sum_{i=0}^{2m-1} a_1^{2^i}  +  \sum_{i=0}^{m-1} a_1^{2^(2i + 1)}
                     = u * Tr_F(a_1)                    +  \sum_{i=0}^{m-1} a_1^{2^(2i + 1)}

                     = \sum_{i=0}^{m-1} a_1^{2^(2i + 1)}
                     [ since Tr_F(a_1) is 0 for all a_1 ]

                     = \sum_{i=0}^{m-1} a_1^{2^(2i) * 2}
                     [we get all of the odd numbers from 1 to m-1.  What happens once 2i+1 >= m ?  If m is even, then we will get
    all of the odd numbers again.]

                     [if m is odd, then we will get the even numbers, so we end up with Tr(a_1)]

                     [if m is even, then we will get the odd numbers again, so we end up with 0]
    **/
    return trace(F.base_field(), get<1>(a));
  }

  /**
   * sqrt
   **/
  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class E),
      /*condition*/(is_element<E>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      sqrt,
      QuadraticExtension,
      F,
      Element,
      result,
      (E const &a),
  {
        sqrt(F.base_field(), result[0], add(F.base_field(), get<0>(a), get<1>(a)));
        sqrt(F.base_field(), result[1], get<1>(a));
      });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class = void),
      /*condition*/true,
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      sqrt,
      QuadraticExtension,
      F,
      typename BaseField::Element,
      result,
      (typename BaseField::Element const &a),
  {
    sqrt(F.base_field(), get<0>(result), a);
    set_zero(F.base_field(), get<1>(result));
      });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseElement),
      /*condition*/(is_field_element<BaseField, BaseElement>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      sqrt,
      QuadraticExtension,
      F,
      QuadraticUp1<decltype(sqrt(std::declval<BaseField const &>(), std::declval<BaseElement const &>()))>,
      result,
      (QuadraticU<BaseElement> const &a),
  {
        sqrt(F.base_field(), get<0>(result), a.value);
        copy_0_1(F, result);
      });

  JBMS_BINARY_FIELD_DEFINE_OP_CASE(
      /*template params*/(class BaseElement),
      /*condition*/(is_field_element<BaseField, BaseElement>::value),
      /*out-arg condition*/ true,
      /*prefix*/ friend,
      sqrt,
      QuadraticExtension,
      F,
      QuadraticU<decltype(sqrt(std::declval<BaseField const &>(), std::declval<BaseElement const &>()))>,
      result,
      (QuadraticUp1<BaseElement> const &a),
  {
        sqrt(F.base_field(), get<1>(result), a.value);
        set_zero(F, result);
      });

  /**
   * get_bit
   **/
  friend bool get_bit(QuadraticExtension const &F, Element const &a, size_t i) {
    size_t degree = F.degree();
    return get_bit(F.base_field(), a[i / degree], i % degree);
  }

  friend bool get_bit(QuadraticExtension const &F, Zero const &, size_t i) { return false; }
  friend bool get_bit(QuadraticExtension const &F, One const &, size_t i) { return i == 0; }

  template <class BaseElement, JBMS_ENABLE_IF(is_field_element<BaseField,BaseElement>)>
  friend bool get_bit(QuadraticExtension const &F, QuadraticU<BaseElement> const &a, size_t i) {
    size_t degree = F.degree();
    return i >= degree && get_bit(F.base_field(), a.value, i);
  }

  friend bool get_bit(QuadraticExtension const &F, typename BaseField::Element const &a, size_t i) {
    return get_bit(F.base_field(), a, i);
  }

  template <class BaseElement, JBMS_ENABLE_IF(is_field_element<BaseField,BaseElement>)>
  friend bool get_bit(QuadraticExtension const &F, QuadraticUp1<BaseElement> const &a, size_t i) {
    size_t degree = F.degree();
    return get_bit(F.base_field(), a.value, i % degree);
  }

  friend void set_bit(QuadraticExtension const &F, Element &a, size_t i, bool value) {
    size_t degree = F.degree();
    set_bit(F.base_field(), a[i / degree], i % degree, value);
  }

  friend void set_in_qs_image(QuadraticExtension const &F, Element &x) {
    set_in_qs_image(F.base_field(), x[0]);
  }

private:
  BaseField base_field_;
};

}
}

#endif /* HEADER GUARD */
