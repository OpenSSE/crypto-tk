#ifndef HEADER_GUARD_1cbf305d71ddb85c7f3b1da4fb2094d0
#define HEADER_GUARD_1cbf305d71ddb85c7f3b1da4fb2094d0

#include <type_traits>
#include <boost/range/iterator_range.hpp>
#include <string>
#include <vector>
#include <array>
#include <initializer_list>

namespace jbms {

template <class T>
struct is_contiguous_range : std::false_type {};

template <class T, class Allocator>
struct is_contiguous_range<std::vector<T,Allocator>> : std::true_type {};

template <class T, class CharTraits, class Allocator>
struct is_contiguous_range<std::basic_string<T,CharTraits,Allocator>> : std::true_type {};

template <class T, size_t N>
struct is_contiguous_range<std::array<T,N>> : std::true_type {};

template <class T, size_t N>
struct is_contiguous_range<T[N]> : std::true_type {};

template <class T>
struct is_contiguous_range<boost::iterator_range<T *>> : std::true_type {};

template <class T>
struct is_contiguous_range<std::initializer_list<T>> : std::true_type {};

}

#endif /* HEADER GUARD */
