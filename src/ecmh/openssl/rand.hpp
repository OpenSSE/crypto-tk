#ifndef HEADER_GUARD_150cedda09269cb541726f767911f2cd
#define HEADER_GUARD_150cedda09269cb541726f767911f2cd

#include <openssl/rand.h>
#include "./error.hpp"
#include "ecmh/array_view/array_view.hpp"

namespace jbms {
namespace openssl {

inline void rand_bytes(array_view<void> buf) {
  if (buf.size() > std::numeric_limits<int>::max())
    throw std::invalid_argument("buf.size()=" + std::to_string(buf.size()) + " > " +
                                std::to_string(std::numeric_limits<int>::max()));
  throw_last_error_if(RAND_bytes(buf.data(), (int)buf.size()) != 1);
}

inline void rand_pseudo_bytes(array_view<void> buf) {
  if (buf.size() > std::numeric_limits<int>::max())
    throw std::invalid_argument("buf.size()=" + std::to_string(buf.size()) + " > " +
                                std::to_string(std::numeric_limits<int>::max()));
  throw_last_error_if(RAND_pseudo_bytes(buf.data(), (int)buf.size()) != 1);
}


}
}

#endif /* HEADER GUARD */
