#ifndef HEADER_GUARD_1bc8cdcc176397f42ce47091b8681bcb
#define HEADER_GUARD_1bc8cdcc176397f42ce47091b8681bcb

#include <string>
#include <openssl/err.h>
// Call ERR_load_crypto_strings() or SSL_load_error_strings() to get better error strings

namespace jbms {
namespace openssl {

class error : public std::exception {
public:
  using Code = unsigned long;
private:
  Code code_;
  mutable std::string error_string_;
public:
  error(Code e) : code_(e) {}
  Code code() const { return code_; }
  virtual ~error() {}
  std::string const &error_string() const {
    if (error_string_.empty()) {
      char buf[120];
      ERR_error_string_n(code_, buf, 120);
      error_string_ = buf;
    }
    return error_string_;
  }
  const char *library() const { return ERR_lib_error_string(code_); }
  const char *function() const { return ERR_func_error_string(code_); }
  const char *reason() const { return ERR_reason_error_string(code_); }
  virtual const char *what() const throw() {
    return error_string().c_str();
  }
  static error from_last_error() {
    return error(ERR_get_error());
  }
};

inline void throw_last_error() {
  throw error::from_last_error();
}

inline void throw_last_error_if(bool condition) {
  if (condition)
    throw_last_error();
}

}
}

#endif /* HEADER GUARD */
