#ifndef HEADER_GUARD_19e901576d45a881dc8af8e71c9afbb9
#define HEADER_GUARD_19e901576d45a881dc8af8e71c9afbb9

#include "./polynomial_base.hpp"
#include "ecmh/utility/static_repeat.hpp"
#include <boost/integer.hpp>

namespace jbms {
namespace binary_field {

template <size_t BlockBits, size_t Bits, JBMS_DISABLE_IF_C(BlockBits == 8)>
void apply_linear_table_transform(BinaryPolynomial<Bits> &z, BinaryPolynomial<Bits> const &x,
                                  const BinaryPolynomial<Bits> table[(Bits+BlockBits-1)/BlockBits][1<<BlockBits]) {
  BinaryPolynomial<Bits> result;
  set_zero(result);
  constexpr int num_blocks = (Bits + BlockBits - 1) / BlockBits;

  constexpr uint64_t lookup_mask = (uint64_t(1) << BlockBits) - 1;

  for (int block_i = 0; block_i < num_blocks; ++block_i) {
    int bit_off = block_i * BlockBits;
    int limb_i = bit_off / limb_bits;
    int word_i = (bit_off % limb_bits) / word_bits;
    int word_off = bit_off % word_bits;
    result += table[block_i][(x.limbs[limb_i][word_i] >> word_off) & lookup_mask];
  }
  z = result;
}


// Special case for BlockBits == 8
// While this code also works for BlockBits == 16, it is actually slower so we don't use it
template <size_t BlockBits, size_t Bits, JBMS_ENABLE_IF_C(BlockBits == 8)>
void apply_linear_table_transform(BinaryPolynomial<Bits> &z,
                                  BinaryPolynomial<Bits> const &x,
                                  const BinaryPolynomial<Bits> table[(Bits + BlockBits - 1) / BlockBits][1 << BlockBits]) {
  BinaryPolynomial<Bits> result;
  set_zero(result);
  constexpr int num_blocks = (Bits+BlockBits-1)/BlockBits;

  using BlockT = typename boost::uint_t<BlockBits>::exact;
  union U {
    U() {}
    BinaryPolynomial<Bits> x_value;
    BlockT x_data[num_blocks];
  } x_temp;
  x_temp.x_value = x;

#if 1
  for (int block_i = 0; block_i < num_blocks; ++block_i) {
    result += table[block_i][x_temp.x_data[block_i]];
  }
#else
  static_repeat<num_blocks>([&](auto block_i) { result += table[block_i][x_temp.x_data[block_i]]; });
#endif
  z = result;
}


}
}

#endif /* HEADER GUARD */
