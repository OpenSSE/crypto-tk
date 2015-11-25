#ifndef HEADER_GUARD_52b81bf2c56c1174685ede7991aff0b4
#define HEADER_GUARD_52b81bf2c56c1174685ede7991aff0b4

namespace jbms {

template <class T, class U>
inline constexpr auto div_floor(T num, U den) {
  return num / den + (((num % den) < 0) ? -1 : 0);
}

template <class T, class U>
inline constexpr auto div_ceil(T num, U den) {
  return num / den + (((num % den) > 0) ? 1 : 0);
}

}

#endif /* HEADER GUARD */
