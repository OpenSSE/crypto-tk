#ifndef HEADER_GUARD_b7dccc883a4b8c7f52e22f517acca323
#define HEADER_GUARD_b7dccc883a4b8c7f52e22f517acca323

#include "./detail/field_operation_helpers.hpp"
#include "./invert_blinded.hpp"
#include "ecmh/array_view/array_view.hpp"
#include <boost/iterator/iterator_traits.hpp>
#include <boost/range/functions.hpp>
#include <boost/range/value_type.hpp>

namespace jbms {
namespace binary_field {

/**
 * Computes output_it[i] := invert(F, input[i]) for 0 <= i < input.size()
 *
 * Using Montgomery's trick, requires only a single field inversion and 3 * (input.size() - 1) field multiplications.
 *
 * OutputIterator need only be an output iterator.
 *
 * InputRange must be a bidirectional range.
 *
 * output_it may equal input.begin()
 * However, output and input must either overlap completely or not at all; a partial overlap is not permitted.
 **/

#define JBMS_BINARY_FIELD_DEFINE_BATCH_INVERT(invert_fn, enable_condition, buffer_declaration)                                 \
  template <class Field,                                                                                                       \
            class OutputIterator,                                                                                              \
            class InputRange,                                                                                                  \
            JBMS_ENABLE_IF_C(is_field<Field>::value &&enable_condition &&                                                      \
                                 std::is_same<typename Field::Element,                                                         \
                                              typename boost::range_value<std::remove_reference_t<InputRange>>::type>::value)> \
  void batch_##invert_fn(Field const &F, OutputIterator output_it, InputRange const &input) {                                  \
    size_t sz = boost::size(input);                                                                                            \
    if (sz == 0)                                                                                                               \
      return;                                                                                                                  \
    if (sz == 1) {                                                                                                             \
      *output_it = invert_fn(F, *boost::begin(input));                                                                         \
      return;                                                                                                                  \
    }                                                                                                                          \
    using FE = typename Field::Element;                                                                                        \
    buffer_declaration;                                                                                                    \
    /*FE *temp_buffer = (FE *)alloca(sizeof(FE)*(sz - 2));*/                                                                       \
    /* temp_buffer[i] = a_{i+1}  */                                                                                            \
    auto input_it = boost::prior(boost::end(input)), input_begin = boost::begin(input);                                        \
    FE cumulative = *input_it;                                                                                                 \
    --input_it;                                                                                                                \
    auto temp_it = &temp_buffer[0];                                                                                            \
    while (input_it != input_begin) {                                                                                          \
      multiply(F, cumulative, cumulative, *input_it);                                                                          \
      --input_it;                                                                                                              \
      *temp_it = cumulative;                                                                                                   \
      ++temp_it;                                                                                                               \
    }                                                                                                                          \
    multiply(F, cumulative, cumulative, *input_it);                                                                            \
    invert_fn(F, cumulative, cumulative);                                                                                      \
    --temp_it;                                                                                                                 \
    auto input_end_minus_2 = boost::prior(boost::prior(boost::end(input)));                                                    \
    while (input_it != input_end_minus_2) {                                                                                    \
      auto input_val = *input_it;                                                                                              \
      ++input_it;                                                                                                              \
      *output_it = multiply(F, cumulative, *temp_it);                                                                          \
      ++output_it;                                                                                                             \
      --temp_it;                                                                                                               \
      multiply(F, cumulative, cumulative, input_val);                                                                          \
    }                                                                                                                          \
    auto input_val = *input_it;                                                                                                \
    ++input_it;                                                                                                                \
    *output_it = multiply(F, cumulative, *input_it);                                                                           \
    ++output_it;                                                                                                               \
    *output_it = multiply(F, cumulative, input_val);                                                                           \
  } /**/

// clang doesn't allow runtime-bound arrays of non-POD types, so we need a separate heap-allocating implementation
// This code gets instantiated during testing with jbms::openssl::bignum
#define JBMS_BINARY_FIELD_DEFINE_BATCH_INVERT2(invert_fn)                                                               \
  JBMS_BINARY_FIELD_DEFINE_BATCH_INVERT(invert_fn, std::is_pod<typename Field::Element>::value, FE *temp_buffer = (FE *)alloca(sizeof(FE)*(sz - 2))) \
      JBMS_BINARY_FIELD_DEFINE_BATCH_INVERT(                                                                            \
          invert_fn, !std::is_pod<typename Field::Element>::value, std::vector<FE> temp_buffer(sz - 2))                 \
      /**/
JBMS_BINARY_FIELD_DEFINE_BATCH_INVERT2(invert)
JBMS_BINARY_FIELD_DEFINE_BATCH_INVERT2(invert_blinded)

#undef JBMS_BINARY_FIELD_DEFINE_BATCH_INVERT2
#undef JBMS_BINARY_FIELD_DEFINE_BATCH_INVERT

}
}

#endif /* HEADER GUARD */
