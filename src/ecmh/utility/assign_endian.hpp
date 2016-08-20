#ifndef HEADER_GUARD_5f5166ea2f33cf07f9c13b54881c9e3b
#define HEADER_GUARD_5f5166ea2f33cf07f9c13b54881c9e3b

#include <boost/endian/conversion.hpp>
#include "ecmh/utility/is_resizable_container.hpp"

namespace jbms {

template <class Data_, boost::endian::order order_>
struct endian_wrapper {
  using Data = Data_;
  using order_type = std::integral_constant<boost::endian::order,order_>;
  constexpr static boost::endian::order order = order_;
  Data &data;
  explicit endian_wrapper(Data &d) : data(d) {}

  // template <class AssignTo,
            // decltype(assign(std::declval<AssignTo &>(), std::declval<endian_wrapper>())) * = nullptr>
  template <class AssignTo>
  explicit operator AssignTo() const {
    AssignTo result;
    assign(result, *this);
    return result;
  }

  // template <class AssignFrom,
            // decltype(assign(std::declval<endian_wrapper>(), std::declval<AssignFrom const &>())) * = nullptr>
  template <class AssignFrom>
  endian_wrapper const &operator=(AssignFrom const &x) const {
    assign(*this, x);
    return *this;
  }

  void ensure_size_equals(size_t n) {
    ensure_container_size_equals(data, n);
  }
};

template <boost::endian::order order, class T>
auto make_endian_wrapper(T const &a) {
  return endian_wrapper<T const, order>(a);
}


template <boost::endian::order order, class T>
auto make_endian_wrapper(T &a) {
  return endian_wrapper<T, order>(a);
}

template <class T>
auto little_endian(T &&a) { return make_endian_wrapper<boost::endian::order::little>(std::forward<T>(a)); }

template <class T>
auto big_endian(T &&a) { return make_endian_wrapper<boost::endian::order::big>(std::forward<T>(a)); }

}

#endif /* HEADER GUARD */
