#ifndef HEADER_GUARD_6c15c5a227acc364c5408216a0db1f43
#define HEADER_GUARD_6c15c5a227acc364c5408216a0db1f43

#include <stdint.h>
#include <string.h> // for size_t

namespace jbms {
namespace binary_field {


typedef uint64_t limb_t __attribute__ ((__vector_size__ (16), __may_alias__));
using word_t = uint64_t;

constexpr size_t limb_bits = 128;
constexpr size_t word_bits = 64;

}
}

#endif /* HEADER GUARD */
