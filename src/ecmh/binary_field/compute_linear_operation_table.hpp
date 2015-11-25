#ifndef HEADER_GUARD_0cce9e7fd4c0c2c2f09a5f908eb4bdd2
#define HEADER_GUARD_0cce9e7fd4c0c2c2f09a5f908eb4bdd2

namespace jbms {
namespace binary_field {

template <size_t BlockBits, size_t Bits, class Op>
void compute_linear_operation_table(BinaryPolynomial<Bits> table[(Bits+BlockBits-1)/BlockBits][1<<BlockBits],
                                    Op &&op) {
  std::array<BinaryPolynomial<Bits>,Bits> monomial_results;
  for (size_t i = 0; i < Bits; ++i) {
    BinaryPolynomial<Bits> x;
    set_zero(x);
    x.set_bit(i);
    monomial_results[i] = op(x);
  }

  constexpr size_t num_blocks = (Bits + BlockBits - 1) / BlockBits;
  constexpr size_t max_val = (size_t(1) << BlockBits);


  for (size_t block_i = 0; block_i < num_blocks; ++block_i) {
    for (size_t val = 0; val < max_val; ++val) {
      BinaryPolynomial<Bits> x;
      set_zero(x);
      size_t base_bit = block_i * BlockBits;
      size_t max_bit = std::min(BlockBits, Bits - base_bit);
      for (size_t bit_i = 0; bit_i < max_bit; ++bit_i) {
        if ((val >> bit_i) & 1)
          x += monomial_results[bit_i + base_bit];
      }
      table[block_i][val] = x;
    }
  }
}

}
}

#endif /* HEADER GUARD */
