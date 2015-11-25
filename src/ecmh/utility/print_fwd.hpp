#ifndef HEADER_GUARD_31defa90d0c0effd7ff8f53a71fd30ab
#define HEADER_GUARD_31defa90d0c0effd7ff8f53a71fd30ab

#include <ostream>

namespace jbms {

template <class T>
struct printer_specialization {
  template <class CharT, class Traits>
  static void do_print(std::basic_ostream<CharT,Traits> &os, T const &x) {
    os << x;
  }
};


template <class CharT, class Traits, class T>
std::basic_ostream<CharT,Traits> &print(std::basic_ostream<CharT,Traits> &os, T const &a) {
  printer_specialization<T>::do_print(os, a);
  return os;
}

template <class T>
struct PrintWrapper;


template <class T>
struct printer_specialization<PrintWrapper<T>> {
  template <class CharT, class Traits>
  static void do_print(std::basic_ostream<CharT,Traits> &os, PrintWrapper<T> const &x) {
    print(os, x.value);
  }
};


template <class T>
struct PrintWrapper {
  T value;

  // For some reason, if we don't make this a template, there are obscure errors when instantiating it with array_view.
  template <class U>
  PrintWrapper(U &&value_) : value(std::forward<U>(value_)) {}

  template <class CharT, class Traits>
  friend std::basic_ostream<CharT, Traits> &operator<<(std::basic_ostream<CharT, Traits> &os, PrintWrapper<T> const &p) {
    return print(os, p.value);
  }
};

/**
 * @brief Returns a proxy object that holds a reference to \p obj and supports streaming to an output stream.
 **/
template <class T>
PrintWrapper<T const &> streamable(T const &obj) {
  return PrintWrapper<T const &>(obj);
}

template <>
struct printer_specialization<unsigned char> {
  template <class CharT, class Traits>
  static void do_print(std::basic_ostream<CharT,Traits> &os, unsigned char x) {
    // print as number
    os << (size_t)x;
  }
};

#define JBMS_RANGE_PRINTER_SPECIALIZATION(...)                                              \
  struct printer_specialization<__VA_ARGS__> {                                              \
    template <class CharT, class Traits>                                                    \
    static void do_print(std::basic_ostream<CharT, Traits> &os, __VA_ARGS__ const &range) { \
      os << CharT('{');                                                                     \
      bool is_first = true;                                                                 \
      for (auto &&y : range) {                                                              \
        if (!is_first)                                                                      \
          os << CharT(',');                                                                 \
        os << CharT(' ');                                                                   \
        is_first = false;                                                                   \
        print(os, y);                                                                       \
      }                                                                                     \
      if (!is_first)                                                                        \
        os << CharT(' ');                                                                   \
      os << CharT('}');                                                                     \
    }                                                                                       \
  } /**/
}

#endif /* HEADER GUARD */
