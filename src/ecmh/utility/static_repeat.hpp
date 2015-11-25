#ifndef HEADER_GUARD_9d6c8b598f9ba2d32d4f6ff63e641093
#define HEADER_GUARD_9d6c8b598f9ba2d32d4f6ff63e641093

#include <cstddef>
#include <utility>

namespace jbms {

template <class Function, std::size_t... Is>
inline void static_repeat(Function &&f, std::index_sequence<Is...>) {
  auto l = { 0, (f(std::integral_constant<size_t,Is>{}),0)... };
  (void)l;
}


template <std::size_t N, class Function>
inline void static_repeat(Function &&f) {
  static_repeat(std::forward<Function>(f), std::make_index_sequence<N>{});
}

}

#endif /* HEADER GUARD */
