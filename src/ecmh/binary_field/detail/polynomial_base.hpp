#ifndef HEADER_GUARD_e4e7a8dd7aeca5890825d668edd9828f
#define HEADER_GUARD_e4e7a8dd7aeca5890825d668edd9828f

#include "./limb_ops.hpp"
#include "ecmh/utility/enable_if.hpp"
#include "ecmh/utility/division.hpp"
#include <initializer_list>
#include <iomanip>
#include <sstream>
#include <algorithm>

#include "ecmh/utility/is_byte.hpp"
#include "ecmh/utility/assign_endian.hpp"
#include <boost/endian/conversion.hpp>
#include <boost/algorithm/hex.hpp>
#include "ecmh/utility/logical.hpp"

#include "random.hpp"

namespace jbms {
namespace binary_field {

template <size_t Bits>
class BinaryPolynomial {
public:
  constexpr static size_t num_limbs = div_ceil(Bits, limb_bits);

  constexpr static size_t num_bits = Bits;
  constexpr static size_t num_bytes = div_ceil(Bits, 8);

private:
  constexpr static limb_t last_limb_mask_(size_t last_bits) {
    return limb_t{last_bits >= word_bits ? ~word_t(0) : (word_t(1) << last_bits) - 1,
        last_bits == limb_bits ? ~word_t(0) : (word_t(1) << (last_bits >= word_bits ? last_bits - word_bits : 0)) - 1};
  }

public:

  constexpr static limb_t last_limb_mask() {
    return last_limb_mask_(Bits - (num_limbs - 1) * limb_bits);
  }

  BinaryPolynomial &operator+=(BinaryPolynomial const &x) {
    for (size_t i = 0; i < num_limbs; ++i)
      limbs[i] ^= x.limbs[i];
    return *this;
  }
  limb_t limbs[num_limbs];

  BinaryPolynomial() = default; // uninitialized

  // Construct from little endian sequence of limb_t
  template <class... T, JBMS_ENABLE_IF(jbms::and_<std::is_same<limb_t,T>...>)>
  constexpr explicit BinaryPolynomial(T ...x) : limbs { x... } {}

private:

  // Helper for constructor that takes a sequence of words.
  // Is must be 0, ..., (N+1)/2 - 1
  template <size_t N, size_t... Is>
  constexpr explicit BinaryPolynomial(word_t const (&arr)[N], std::integer_sequence<size_t,Is...>)
    : limbs { {arr[Is*2], (Is*2+1 < N ? arr[Is*2+1] : 0)}... } {}

  // Helper type needed for specifying array argument for the above constructor
  template <size_t N>
  using word_arr_t = word_t[N];
public:

  // Construct from little endian sequence of word_t
  // template <class... T, JBMS_ENABLE_IF(jbms::and_<std::is_same<word_t,T>...>)>
  // constexpr explicit BinaryPolynomial(T... x)
  //   : BinaryPolynomial(word_arr_t<sizeof...(T)>{x...},
  //                      std::make_integer_sequence<size_t,(sizeof...(T) + 1)/2>{})
  // {}
  template <class... T>
  constexpr explicit BinaryPolynomial(T... x)
    : BinaryPolynomial(word_arr_t<sizeof...(T)>{x...},
                       std::make_integer_sequence<size_t,(sizeof...(T) + 1)/2>{})
  {}

  // little endian order
  constexpr word_t get_word(size_t i) const {
    return limbs[i / 2][i % 2];
  }

  void set_word(size_t i, word_t w) {
    limbs[i / 2][i % 2] = w;
  }

  // 0th bit is the least significant bit
  constexpr bool get_bit(size_t i) const {
    return (get_word(i / word_bits) >> (i % word_bits)) & 1;
  }

  void set_bit(size_t i, bool b = true) {
    auto word_i = i / word_bits;
    auto word_off = i % word_bits;
    auto w = get_word(word_i);
    w &= ~(word_t(1) << word_off);
    w |= (word_t(b) << word_off);
    set_word(word_i, w);
  }

  // Returns the bit at (little-endian) position i
  bool operator[](size_t i) const {
    return get_bit(i);
  }

  constexpr uint8_t get_byte(size_t i) const {
    auto word_i = i / sizeof(word_t);
    auto word_off = i % sizeof(word_t);
    return (uint8_t)(get_word(word_i) >> (word_off * 8));
  }

  void set_byte(size_t i, uint8_t b) {
    auto word_i = i / sizeof(word_t);
    auto word_off = i % sizeof(word_t);
    auto w = get_word(word_i) & ~(word_t(0xFF) << (word_off * 8));
    w |= (word_t(b) << (word_off * 8));
    set_word(word_i, w);
  }
};

template <size_t Bits>
constexpr size_t BinaryPolynomial<Bits>::num_bytes;

template <size_t Bits>
constexpr size_t BinaryPolynomial<Bits>::num_limbs;

template <size_t Bits>
constexpr size_t BinaryPolynomial<Bits>::num_bits;


template <size_t Bits>
inline bool operator==(BinaryPolynomial<Bits> const &a, BinaryPolynomial<Bits> const &b) {
  limb_t result {0,0};
  for (size_t i = 0; i < a.num_limbs; ++i) {
    // a.limbs[i] != b.limbs[i] produces a vector with components equal to 0 if equal and -1 (all bits set) if unequal
    result |= (a.limbs[i] != b.limbs[i]);
  }
  // result will have a one-bit if something was unequal
  return (result[0] | result[1]) == 0;
  // FIXME: maybe use optimized x86_64 version
  //return _mm_movemask_epi8(result) == 0;
}

template <size_t Bits>
inline bool operator!=(BinaryPolynomial<Bits> const &a, BinaryPolynomial<Bits> const &b) {
  return !(a == b);
}

template <size_t Bits>
inline void set_zero(BinaryPolynomial<Bits> &x) {
  for (size_t i = 0; i < x.num_limbs; ++i)
    x.limbs[i] = limb_t{0,0};
}

template <size_t Bits>
inline void assign(BinaryPolynomial<Bits> &x, bool value) {
  x.limbs[0] = limb_t{value,0};
  for (size_t i =1; i < x.num_limbs; ++i)
    x.limbs[i] = limb_t{0,0};
}

template <size_t Bits>
inline void set_one(BinaryPolynomial<Bits> &x) {
  x.limbs[0] = limb_t{1,0};
  for (size_t i =1; i < x.num_limbs; ++i)
    x.limbs[i] = limb_t{0,0};
}

template <size_t Bits>
inline bool is_zero(BinaryPolynomial<Bits> const &a) {
  BinaryPolynomial<Bits> x;
  set_zero(x);
  return a == x;
}

template <size_t Bits>
inline bool is_zero_constant_time(BinaryPolynomial<Bits> const &x) {
  limb_t combined = x.limbs[0];
  for (size_t i = 1; i < x.num_limbs; ++i)
    combined |= x.limbs[i];
  return is_zero_constant_time(combined);
}

template <size_t Bits>
inline BinaryPolynomial<Bits> select_constant_time(BinaryPolynomial<Bits> const &a,
                                                   BinaryPolynomial<Bits> const &b,
                                                   bool condition) {
  BinaryPolynomial<Bits> result;
  for (size_t i = 0; i < result.num_limbs; ++i)
    result.limbs[i] = select_constant_time(a.limbs[i], b.limbs[i], condition);
  return result;
}

template <size_t Bits>
inline BinaryPolynomial<Bits> operator|(BinaryPolynomial<Bits> const &a,
                                        BinaryPolynomial<Bits> const &b) {
  BinaryPolynomial<Bits> result;
  for (size_t i = 0; i < result.num_limbs; ++i)
    result.limbs[i] = a.limbs[i] | b.limbs[i];
  return result;
}

template <size_t Bits>
inline void assign_random(BinaryPolynomial<Bits> &result) {
	sse::crypto::random_bytes(result.num_limbs*sizeof(limb_t), (unsigned char*)&result.limbs);
  result.limbs[result.num_limbs-1] &= result.last_limb_mask();
}

template <size_t Bits>
inline bool is_one(BinaryPolynomial<Bits> const &a) {
  BinaryPolynomial<Bits> x;
  set_one(x);
  return a == x;
}

template <size_t Bits>
inline BinaryPolynomial<Bits> operator+(BinaryPolynomial<Bits> const &a, BinaryPolynomial<Bits> const &b) {
  BinaryPolynomial<Bits> result = a;
  result += b;
  return result;
}

// result must have size == x.num_bytes
template <size_t Bits, class Dest, JBMS_ENABLE_IF(is_byte_range<Dest>)>
void assign(endian_wrapper<Dest,boost::endian::order::little> dest,
            BinaryPolynomial<Bits> const &x) {
  dest.ensure_size_equals(x.num_bytes);

  BinaryPolynomial<Bits> temp = x;
  for (auto &limb : temp.limbs) {
    limb[0] = boost::endian::native_to_little(limb[0]);
    limb[1] = boost::endian::native_to_little(limb[1]);
  }
  std::copy_n((uint8_t const *)temp.limbs, dest.data.size(), dest.data.data());
}


// result must have size x.num_bytes
template <size_t Bits, class Dest, JBMS_ENABLE_IF(is_byte_range<Dest>)>
void assign(endian_wrapper<Dest,boost::endian::order::big> dest,
            BinaryPolynomial<Bits> const &x) {
  dest.ensure_size_equals(x.num_bytes);

  BinaryPolynomial<Bits> temp;
  // reverse order of limbs
  std::reverse_copy(&x.limbs[0], &x.limbs[x.num_limbs], &temp.limbs[0]);
  for (auto &limb : temp.limbs) {
    auto tmp = boost::endian::native_to_big(limb[1]);
    limb[1] = boost::endian::native_to_big(limb[0]);
    limb[0] = tmp;
  }
  std::copy_n(((uint8_t *)&temp.limbs[temp.num_limbs]) - temp.num_bytes, dest.data.size(), dest.data.data());
}

template <size_t Bits, class Source, JBMS_ENABLE_IF(is_byte_range<Source>)>
void assign(BinaryPolynomial<Bits> &x, endian_wrapper<Source,boost::endian::order::big> source) {
  size_t source_size = source.data.size();
  size_t num_bytes = std::min(source_size, x.num_bytes);
  set_zero(x);
  uint8_t *result_ptr = (uint8_t *)&x.limbs[0];
  // Reverse input bytes, so that we end up with a little-endian representation.
  for (size_t i = 0; i < num_bytes; ++i)
    result_ptr[i] = source.data[source_size-i-1];
  // Convert to native endian.
  for (auto &limb : x.limbs) {
    limb[0] = boost::endian::little_to_native(limb[0]);
    limb[1] = boost::endian::little_to_native(limb[1]);
  }
  x.limbs[x.num_limbs-1] &= x.last_limb_mask();
}

template <size_t Bits, class Source, JBMS_ENABLE_IF(is_byte_range<Source>)>
void assign(BinaryPolynomial<Bits> &x, endian_wrapper<Source,boost::endian::order::little> source) {
  size_t source_size = source.data.size();
  size_t num_bytes = std::min(source_size, x.num_bytes);
  set_zero(x);
  uint8_t *result_ptr = (uint8_t *)&x.limbs[0];
  for (size_t i = 0; i < num_bytes; ++i)
    result_ptr[i] = source.data[i];
  // Convert to native endian.
  for (auto &limb : x.limbs) {
    limb[0] = boost::endian::little_to_native(limb[0]);
    limb[1] = boost::endian::little_to_native(limb[1]);
  }
  x.limbs[x.num_limbs-1] &= x.last_limb_mask();
}

template <size_t Bits, class Range>
void assign_from_hex(BinaryPolynomial<Bits> &x, Range const &s) {
  std::vector<uint8_t> byte_str;
  if (s.size() % 2 == 1) {
    std::string temp;
    temp += '0';
    temp.append(s.begin(), s.end());
    boost::algorithm::unhex(temp, std::back_inserter(byte_str));
  } else {
    boost::algorithm::unhex(s, std::back_inserter(byte_str));
  }
  assign(x, big_endian(byte_str));
}

// Returns a big-endian hex string.  No extra zero-padding is included.
template <size_t Bits>
std::string to_hex(BinaryPolynomial<Bits> const &x) {
  std::ostringstream ostr;
  ostr << std::setfill('0') << std::hex;
  bool seen_non_zero = false;
  for (int limb = x.num_limbs - 1; limb >= 0; --limb) {
    for (int part = 1; part >= 0; --part) {
      bool last_part = (part == 0 && limb == 0);
      if (last_part || x.limbs[limb][part] != 0) {
        if (seen_non_zero)
          ostr << std::setw(16);
        seen_non_zero = true;
        ostr << x.limbs[limb][part];
      }
    }
  }
  return ostr.str();
}

// Return a big-endian base-2 string.  Length is exactly degree() characters long.
template <size_t Bits>
std::string to_bin(BinaryPolynomial<Bits> const &x) {
  std::ostringstream ostr;
  for (int bit = Bits - 1; bit >= 0; --bit)
    ostr << x.get_bit(bit);
  return ostr.str();
}

}
}

#endif /* HEADER GUARD */
