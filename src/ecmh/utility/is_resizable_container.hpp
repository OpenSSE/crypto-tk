#ifndef HEADER_GUARD_39d2ae75169d92bdeca7ebf7bceaeba2
#define HEADER_GUARD_39d2ae75169d92bdeca7ebf7bceaeba2

#include <type_traits>
#include "ecmh/utility/enable_if.hpp"
#include <stdexcept>
#include <vector>

namespace jbms {

template <class T>
struct is_resizable_container : std::false_type {};

template <class T, class Allocator>
struct is_resizable_container<std::vector<T,Allocator>> : std::true_type {};

template <class T, class CharTraits, class Allocator>
struct is_resizable_container<std::basic_string<T,CharTraits,Allocator>> : std::true_type {};

template <class Container, JBMS_ENABLE_IF(is_resizable_container<std::remove_reference_t<Container>>)>
inline void ensure_container_size_equals(Container &&x, size_t n) {
  x.resize(n);
}

template <class Container, JBMS_DISABLE_IF(is_resizable_container<std::remove_reference_t<Container>>)>
inline void ensure_container_size_equals(Container &&x, size_t n) {
  if (x.size() != n)
    throw std::invalid_argument("container must have correct length");
}

}

#endif /* HEADER GUARD */
