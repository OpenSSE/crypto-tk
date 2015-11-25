#ifndef HEADER_GUARD_8b3ffc59db04215ee913858438020c7d
#define HEADER_GUARD_8b3ffc59db04215ee913858438020c7d

#include "ecmh/utility/enable_if.hpp"
#include "ecmh/utility/logical.hpp"
#include <type_traits>

namespace jbms {
namespace binary_field {

template <class Field>
struct is_field : std::false_type {};

template <class Field, class Element>
struct is_field_element : std::false_type{};

template <class Field>
struct is_field_element<Field, typename Field::Element> : std::true_type{};

template <class Field, class... E>
using are_field_elements = and_<is_field<Field>,is_field_element<Field,E>...>;

struct Zero {};
struct One {};

template <class Field, class Element>
struct is_special_field_element : std::false_type{};

template <class Field>
struct is_field_element<Field,One> : std::true_type{};

template <class Field>
struct is_field_element<Field,Zero> : std::true_type{};

template <class Field>
struct is_special_field_element<Field,One> : std::true_type{};

template <class Field>
struct is_special_field_element<Field,Zero> : std::true_type{};


// If we can assign(Field, ElementDerived, ElementBase)
template <class Field, class ElementBase, class ElementDerived>
struct is_field_element_convertible_to : std::is_same<ElementBase,ElementDerived> {};

template <class Field, class ElementBase>
struct is_field_element_convertible_to<Field,ElementBase,typename Field::Element> : std::true_type {};



/**
 * assign
 **/
template <class Field, class E, JBMS_ENABLE_IF(are_field_elements<Field,E>)>
inline void assign(Field const &F, E &x, Zero const &) {
  set_zero(F, x);
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline void assign(Field const &F, Zero const &, Zero const &) {}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline void set_zero(Field const &F, Zero const &) {}

template <class Field, class E, JBMS_ENABLE_IF_C(are_field_elements<Field,E>::value && !std::is_same<E,One>::value)>
inline void assign(Field const &F, E &x, One const &) {
  set_one(F, x);
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline void set_one(Field const &F, One const &) {}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline void assign(Field const &F, One const &, One const &) {}

template <class Field, class E, JBMS_ENABLE_IF(are_field_elements<Field,E>)>
inline void assign(Field const &F, E &x, E const &y) {
  x = y;
}


template <class Field, class T, JBMS_ENABLE_IF(is_field<Field>),
          decltype(assign(std::declval<Field const &>(),
                          std::declval<typename Field::Element &>(),
                          std::declval<T const &>())) * = nullptr>
inline typename Field::Element convert(Field const &F, T const &value) {
  typename Field::Element x;
  assign(F, x, value);
  return x;
}

template <class Field, class String, JBMS_ENABLE_IF(is_field<Field>)>
inline typename Field::Element from_hex(Field const &F, String const &s) {
  typename Field::Element x;
  assign_from_hex(F, x, s);
  return x;
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline Zero zero_expr(Field const &F) { return {}; }

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline One one_expr(Field const &F) { return {}; }


template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline typename Field::Element zero(Field const &F) {
  typename Field::Element x;
  set_zero(F, x);
  return x;
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline typename Field::Element one(Field const &F) {
  typename Field::Element x;
  set_one(F, x);
  return x;
}

/**
 * equal
 **/
template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline bool equal(Field const &F, typename Field::Element const &a, Zero const &) {
  return is_zero(F, a);
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline bool equal(Field const &F, Zero const &, typename Field::Element const &a) {
  return is_zero(F, a);
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline bool equal(Field const &F, Zero const &, Zero const &) {
  return true;
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline bool equal(Field const &F, typename Field::Element const &a, One const &) {
  return is_one(F, a);
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline bool equal(Field const &F, One const &, typename Field::Element const &a) {
  return is_one(F, a);
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline bool equal(Field const &F, One const &, One const &) {
  return true;
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline bool equal(Field const &F, One const &, Zero const &) {
  return false;
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline bool equal(Field const &F, Zero const &, One const &) {
  return false;
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
constexpr inline bool is_zero(Field const &F, Zero const &) { return true; }

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
constexpr inline bool is_zero(Field const &F, One const &) { return false; }

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
constexpr inline bool is_one(Field const &F, Zero const &) { return false; }

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
constexpr inline bool is_one(Field const &F, One const &) { return true; }


// If the argument is a regular field element, return a const reference to it
template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline typename Field::Element const &as_element(Field const &F, typename Field::Element const &y) {
  return y;
}

template <class Field,
          class E,
          JBMS_ENABLE_IF_C(are_field_elements<Field, E>::value && !std::is_same<E, typename Field::Element>::value)>
inline typename Field::Element as_element(Field const &F, E const &a) {
  typename Field::Element result;
  assign(F, result, a);
  return result;
}


/* to_hex */
template <class Field, class Element, JBMS_ENABLE_IF_C(is_field<Field>::value && is_special_field_element<Field,Element>::value)>
inline std::string to_hex(Field const &F, Element const &e) {
  return to_hex(F, as_element(F, e));
}

#define JBMS_BINARY_FIELD_STRIP_PARENS(...) __VA_ARGS__

#define JBMS_BINARY_FIELD_DEFINE_OP_CASE(                                                                                      \
    template_params, condition, out_arg_condition, prefix, name, field_type, field_name, ret_type, result_name, args, ...)     \
  template <                                                                                                                   \
      JBMS_BINARY_FIELD_STRIP_PARENS template_params,                                                                          \
      class ResultT = void,                                                                                                    \
      JBMS_ENABLE_IF_C(condition &&out_arg_condition &&is_field_element_convertible_to<field_type, ResultT, ret_type>::value)> \
  prefix void name(field_type const &field_name, ResultT &&result_name, JBMS_BINARY_FIELD_STRIP_PARENS args) {                 \
    __VA_ARGS__;                                                                                                               \
  }                                                                                                                            \
  template <JBMS_BINARY_FIELD_STRIP_PARENS template_params, JBMS_ENABLE_IF_C(condition)>                                       \
  prefix auto name(field_type const &field_name, JBMS_BINARY_FIELD_STRIP_PARENS args)->ret_type {                              \
    ret_type result_name;                                                                                                      \
    __VA_ARGS__;                                                                                                               \
    return result_name;                                                                                                        \
  } /**/

#define JBMS_BINARY_FIELD_DEFINE_BINARY_OP_CATCH_ALL(name)                                                             \
  JBMS_BINARY_FIELD_DEFINE_OP_CASE(                                                                                    \
      /*template params*/(class Field, class E1, class E2),                                                            \
      /*condition*/(are_field_elements<Field, E1, E2>::value),                                                         \
      /*out-arg condition*/(is_special_field_element<Field, E1>::value || is_special_field_element<Field, E2>::value), \
      /*prefix*/ inline,                                                                                               \
      /*name*/ name,                                                                                                   \
      Field,                                                                                                           \
      F,                                                                                                               \
      typename Field::Element,                                                                                         \
      result,                                                                                                          \
      (E1 const &a, E2 const &b),                                                                                      \
  { name(F, result, as_element(F, a), as_element(F, b)); })                                                            \
      /**/

#define JBMS_BINARY_FIELD_DEFINE_UNARY_OP_CATCH_ALL(name)                                            \
  JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(class Field, class E),                        \
                                   /*condition*/(are_field_elements<Field, E>::value),               \
                                   /*out-arg condition*/(is_special_field_element<Field, E>::value), \
                                   /*prefix*/ inline,                                                \
                                   name,                                                             \
                                   Field,                                                            \
                                   F,                                                                \
                                   typename Field::Element,                                          \
                                   result,                                                           \
                                   (E const &a),                                                     \
  { name(F, result, as_element(F, a)); }) /**/

#define JBMS_BINARY_FIELD_DEFINE_UNARY_OP_SPECIAL(name, result_type, arg_type, ...) \
  JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(class Field),                \
                                   /*condition*/(is_field<Field>::value),           \
                                   /*out-arg condition*/ true,                      \
                                   /*prefix*/ inline,                               \
                                   name,                                            \
                                   Field,                                           \
                                   F,                                               \
                                   result_type,                                     \
                                   result,                                          \
                                   (arg_type const &),                              \
                                   __VA_ARGS__)                                     \
      /**/

/**
 * add
 **/

JBMS_BINARY_FIELD_DEFINE_BINARY_OP_CATCH_ALL(add)

// Zero + Element
JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(class Field, class Element),
                                 /*condition*/(are_field_elements<Field, Element>::value),
                                 /*out-arg condition*/true,
                                 /*prefix*/inline,
                                 add,
                                 Field,
                                 F,
                                 Element,
                                 result,
                                 (Element const &a, Zero const &),
{ assign(F, result, a); })

// Element + Zero: must exclude Element=Zero to avoid ambiguity with Zero + Element case above
JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(class Field, class Element),
                                 /*condition*/(are_field_elements<Field, Element>::value && !std::is_same<Element, Zero>::value),
                                 /*out-arg condition*/true,
                                 /*prefix*/inline,
                                 add,
                                 Field,
                                 F,
                                 Element,
                                 result,
                                 (Zero const &, Element const &a),
{ assign(F, result, a); })

// One + One
JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(class Field),
                                 /*condition*/(is_field<Field>::value),
                                 /*out-arg condition*/true,
                                 /*prefix*/inline,
                                 add,
                                 Field,
                                 F,
                                 Zero,
                                 result,
                                 (One const &, One const &),
{ set_zero(F, result); })

// DoubleElement + DoubleElement
template <class Field, JBMS_ENABLE_IF_C(is_field<Field>::value &&
                                        !std::is_same<typename Field::Element,typename Field::DoubleElement>::value)>
inline typename Field::DoubleElement add(Field const &F, typename Field::DoubleElement const &a, typename Field::DoubleElement const &b) {
  typename Field::DoubleElement x;
  add(F, x, a, b);
  return x;
}


/**
 * multiply
 **/

// default: define multiply in terms of multiply_no_reduce
template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline void multiply(Field const &F, typename Field::Element &x, typename Field::Element const &a, typename Field::Element const &b) {
  typename Field::DoubleElement temp;
  multiply_no_reduce(F, temp, a, b);
  reduce_after_multiply(F, x, temp);
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline typename Field::DoubleElement multiply_no_reduce(Field const &F, typename Field::Element const &a, typename Field::Element const &b) {
  typename Field::DoubleElement x;
  multiply_no_reduce(F, x, a, b);
  return x;
}


JBMS_BINARY_FIELD_DEFINE_BINARY_OP_CATCH_ALL(multiply)

// One * Element
JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(class Field, class Element),
                                 /*condition*/(are_field_elements<Field, Element>::value && !std::is_same<Element,Zero>::value),
                                 /*out-arg condition*/true,
                                 /*prefix*/inline,
                                 multiply,
                                 Field,
                                 F,
                                 Element,
                                 result,
                                 (Element const &a, One const &),
{ assign(F, result, a); })

// Element * One
JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(class Field, class Element),
                                 /*condition*/(are_field_elements<Field, Element>::value && !std::is_same<Element, Zero>::value &&
                                               !std::is_same<Element, One>::value),
                                 /*out-arg condition*/ true,
                                 /*prefix*/ inline,
                                 multiply,
                                 Field,
                                 F,
                                 Element,
                                 result,
                                 (One const &, Element const &a),
{ assign(F, result, a); })

// Zero * Element
JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(class Field, class Element),
                                 /*condition*/(are_field_elements<Field, Element>::value),
                                 /*out-arg condition*/true,
                                 /*prefix*/inline,
                                 multiply,
                                 Field,
                                 F,
                                 Zero,
                                 result,
                                 (Zero const &, Element const &a),
{ set_zero(F, result); })

// Element * Zero
JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(class Field, class Element),
                                 /*condition*/(are_field_elements<Field, Element>::value && !std::is_same<Element,Zero>::value),
                                 /*out-arg condition*/true,
                                 /*prefix*/inline,
                                 multiply,
                                 Field,
                                 F,
                                 Zero,
                                 result,
                                 (Element const &a, Zero const &),
{ set_zero(F, result); })

/**
 * reduce
 */

// reduce_after_square defaults to reduce_after_multiply
template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline void reduce_after_square(Field const &F, typename Field::Element &z, typename Field::DoubleElement const &r) {
  reduce_after_multiply(F, z, r);
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline typename Field::Element reduce(Field const &F, typename Field::DoubleElement const &r) {
  typename Field::Element z;
  reduce_after_multiply(F, z, r);
  return z;
}

/**
 * square
 **/

// define square in terms of square_no_reduce
template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline void square(Field const &F, typename Field::Element &x, typename Field::Element const &a) {
  typename Field::DoubleElement temp;
  square_no_reduce(F, temp, a);
  reduce_after_square(F, x, temp);
}

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline typename Field::DoubleElement square_no_reduce(Field const &F, typename Field::Element const &a) {
  typename Field::DoubleElement x;
  square_no_reduce(F, x, a);
  return x;
}

JBMS_BINARY_FIELD_DEFINE_UNARY_OP_CATCH_ALL(square)
JBMS_BINARY_FIELD_DEFINE_UNARY_OP_SPECIAL(square, Zero, Zero, { set_zero(F, result); });
JBMS_BINARY_FIELD_DEFINE_UNARY_OP_SPECIAL(square, One, One, { set_one(F, result); });

/**
 * invert
 **/

JBMS_BINARY_FIELD_DEFINE_UNARY_OP_CATCH_ALL(invert)
JBMS_BINARY_FIELD_DEFINE_UNARY_OP_SPECIAL(invert, Zero, Zero, { throw std::logic_error("invert(Zero) not defined"); });
JBMS_BINARY_FIELD_DEFINE_UNARY_OP_SPECIAL(invert, One, One, { set_one(F, result); });

/**
 * sqrt
 **/
JBMS_BINARY_FIELD_DEFINE_UNARY_OP_CATCH_ALL(sqrt)
JBMS_BINARY_FIELD_DEFINE_UNARY_OP_SPECIAL(sqrt, Zero, Zero, { set_zero(F, result); });
JBMS_BINARY_FIELD_DEFINE_UNARY_OP_SPECIAL(sqrt, One, One, { set_one(F, result); });


/**
 * half_trace
 **/
JBMS_BINARY_FIELD_DEFINE_UNARY_OP_CATCH_ALL(half_trace)
JBMS_BINARY_FIELD_DEFINE_UNARY_OP_SPECIAL(half_trace, Zero, Zero, { set_zero(F, result); });

/**
 * solve_quadratic
 **/
JBMS_BINARY_FIELD_DEFINE_UNARY_OP_CATCH_ALL(solve_quadratic)
JBMS_BINARY_FIELD_DEFINE_UNARY_OP_SPECIAL(solve_quadratic, Zero, Zero, { set_zero(F, result); });

/**
 * trace
 **/
template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline constexpr bool trace(Field const &F, Zero const &) { return false; }

template <class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline constexpr bool trace(Field const &F, One const &x) { return (F.degree() % 2); }


/**
 * multi_square
 **/
template <size_t n, class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline void direct_multi_square(Field const &F, typename Field::Element &x, typename Field::Element const &a) {
  x = a;
#if 1
  for (size_t i = 0; i < n; ++i)
    square(F, x, x);
#else
  static_repeat<n>([&](auto i) { square(F, x, x); });
#endif
}

template <size_t n, class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline typename Field::Element direct_multi_square(Field const &F, typename Field::Element const &a) {
  typename Field::Element result;
  direct_multi_square<n>(F, result, a);
  return result;
}

template <size_t n, class Field, JBMS_ENABLE_IF(is_field<Field>)>
inline void multi_square(Field const &F, typename Field::Element &x, typename Field::Element const &a) {
  direct_multi_square<n>(F, x, a);
}

// catch-all
JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(size_t n, class Field, class E),
                                 /*condition*/(are_field_elements<Field, E>::value),
                                 /*out-arg condition*/(is_special_field_element<Field, E>::value),
                                 /*prefix*/ inline,
                                 multi_square,
                                 Field,
                                 F,
                                 typename Field::Element,
                                 result,
                                 (E const &a),
{ multi_square<n>(F, result, as_element(F, a)); })

JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(size_t n, class Field),
                                 /*condition*/(is_field<Field>::value),
                                 /*out-arg condition*/ true,
                                 /*prefix*/ inline,
                                 multi_square,
                                 Field,
                                 F,
                                 Zero,
                                 result,
                                 (Zero const &),
{ set_zero(F, result); })

JBMS_BINARY_FIELD_DEFINE_OP_CASE(/*template params*/(size_t n, class Field),
                                 /*condition*/(is_field<Field>::value),
                                 /*out-arg condition*/ true,
                                 /*prefix*/ inline,
                                 multi_square,
                                 Field,
                                 F,
                                 One,
                                 result,
                                 (One const &),
{ set_one(F, result); })

// Dummy declaration so that set_trace_zero can be found by ADL.
inline void set_trace_zero(std::nullptr_t) {}

// Dummy declaration so that set_in_qs_image can be found by ADL.
inline void set_in_qs_image(std::nullptr_t) {}

}
}

#endif /* HEADER GUARD */
