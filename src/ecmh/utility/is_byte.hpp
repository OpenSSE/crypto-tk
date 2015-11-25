#ifndef HEADER_GUARD_4a5e7e01fcbad2edb30f101e39f4bab7
#define HEADER_GUARD_4a5e7e01fcbad2edb30f101e39f4bab7

#include <type_traits>
#include <boost/range/value_type.hpp>

namespace jbms {

template <class T>
struct is_byte : std::false_type {};

template <>
struct is_byte<char> : std::true_type {};

template <>
struct is_byte<unsigned char> : std::true_type {};

template <class T>
struct is_byte_range
    : is_byte<typename boost::range_value<std::remove_const_t<std::remove_reference_t<T>>>::type> {};

}

#endif /* HEADER GUARD */
