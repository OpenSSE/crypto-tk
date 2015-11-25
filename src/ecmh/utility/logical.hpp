#ifndef HEADER_GUARD_e25017dcfb45f3953cf7c2ff855476ae
#define HEADER_GUARD_e25017dcfb45f3953cf7c2ff855476ae

#include <type_traits>

// See http://ldionne.github.io/mpl11-cppnow-2014/ [page 5-2]

namespace jbms {

template <bool ...> struct bool_seq;

template <typename... xs>
using and_ = std::is_same<
  bool_seq<xs::value...>,
  bool_seq<(xs::value?true:true)...>
  >;

template <class x>
using not_ = std::integral_constant<bool,!x::value>;

template <bool... xs>
using and_c = std::is_same<
  bool_seq<xs...>,
  bool_seq<(xs?true:true)...>
  >;

// or(xs::value...) = not(and(!xs::value...))
template <typename... xs>
using or_ = std::integral_constant<
  bool,
  !std::is_same<
    bool_seq<(!xs::value)...>,
    bool_seq<(xs::value?true:true)...>>::value>;

template <bool... xs>
using or_c = std::integral_constant<
  bool,
  !std::is_same<
    bool_seq<(!xs)...>,
    bool_seq<(xs?true:true)...>>::value>;

}

#endif /* HEADER GUARD */
