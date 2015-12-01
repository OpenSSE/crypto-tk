#ifndef HEADER_GUARD_21b561b7b0ae1e1907174b248d39c344
#define HEADER_GUARD_21b561b7b0ae1e1907174b248d39c344

#include <type_traits>
#include "ecmh/utility/enable_if.hpp"
#include <boost/algorithm/hex.hpp>

namespace jbms {
namespace multiset_hash {

template <class H>
struct is_multiset_hash : std::false_type {};

template <class H, JBMS_ENABLE_IF(is_multiset_hash<H>)>
inline typename H::State initial_state(H const &h) {
  typename H::State s;
  initialize(h, s);
  return s;
}

// Default implementation
template <class H, class ElementRange, JBMS_ENABLE_IF(is_multiset_hash<H>)>
void batch_add(H const &h, typename H::State &state, ElementRange const &element_range) {
  for (auto &&e : element_range)
    add(h, state, e);
}

// Default implementation
template <class H, class ElementRange, JBMS_ENABLE_IF(is_multiset_hash<H>)>
void batch_remove(H const &h, typename H::State &state, ElementRange const &element_range) {
  for (auto &&e : element_range)
    remove(h, state, e);
}

template <class H, JBMS_ENABLE_IF(is_multiset_hash<H>)>
inline typename H::State invert(H const &h, typename H::State const &state) {
  typename H::State result;
  invert(h, result, state);
  return result;
}


template <class H, JBMS_ENABLE_IF(is_multiset_hash<H>)>
std::string to_hex(H const &h, typename H::State const &x) {
    std::vector<uint8_t> temp;
    assign(h, jbms::little_endian(temp), x);
    std::string s;
    boost::algorithm::hex(temp, std::back_inserter(s));
    return s;
  }

template <class H, class Range, JBMS_ENABLE_IF_C(is_multiset_hash<H>::value && std::is_same<char,typename boost::range_value<Range>::type>::value)>
void assign_from_hex(H const &h, typename H::State &x, Range const &s) {
  std::vector<uint8_t> temp;
  boost::algorithm::unhex(s, std::back_inserter(temp));
  assign(h, x, jbms::little_endian(temp));
}

template <class H, class Range, JBMS_ENABLE_IF_C(is_multiset_hash<H>::value && std::is_same<char,typename boost::range_value<Range>::type>::value)>
typename H::State from_hex(H const &h, Range const &s) {
  typename H::State x;
  assign_from_hex(h, x, s);
  return x;
}


}
}

#endif /* HEADER GUARD */
