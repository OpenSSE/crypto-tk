#ifndef HEADER_GUARD_e0438bc676205bb1bb9325dbaee01465
#define HEADER_GUARD_e0438bc676205bb1bb9325dbaee01465

#include "openssl/bn.hpp"
#include "./detail/operation_helpers.hpp"
#include "ecmh/utility/division.hpp"
#include "ecmh/hash/hash_expand.hpp"
#include "ecmh/array_view/array_view.hpp"

namespace jbms {
namespace multiset_hash {

template <class Hash_>
struct MuHash;

template <class Hash_>
struct is_multiset_hash<MuHash<Hash_>> : std::true_type {};

// Note: A single MuHash instance is not thread-safe, since it contains a bn_ctx
template <class Hash_>
struct MuHash {
public:
  using Hash = Hash_;

  struct State {
    openssl::bignum added, removed;
    long r_factor = 0;  // amount by which value is "unnormalized"
    // true hash = added / removed * R^{r_factor} mod p
  };

  friend void initialize(MuHash const &h, State &state) {
    state.r_factor = 0;
    state.added.set_one();
    state.removed.set_one();
  }

  friend void invert(MuHash const &h, State &result, State const &x) {
    result = x;
    result.added.swap(result.removed);
    result.r_factor = -result.r_factor;
  }

  friend void modular_reduce(MuHash const &h, openssl::bignum &x) {
    while (compare(x, h.mont.N()) >= 0) {
      // This should happen at most once if the top bit of our modulus is 1
      sub(x, x, h.mont.N());
    }
  }

  friend void normalize(MuHash const &h, openssl::bignum &result, openssl::bignum const &x, long r_factor) {
    if (r_factor == 0) {
      result = x;
      modular_reduce(h, result);
      return;
    }

    openssl::bn_ctx_frame frame(h.ctx);

    auto &R = frame.get();
    auto &r_factor_bn = frame.get();
    auto &norm_term = frame.get();

    R.set_zero();
    R.set_bit(h.mont->ri);

    /**
     * We need to multiply value by R^{R_factor}.  Since we will do the multiplication using mod_mul_montgomery, we need to
     * multiply by an extra factor of R.
     **/

    r_factor_bn = r_factor + 1; // + 1 because we are using mod_mul_montgomery in here
    mod_exp(norm_term, R, r_factor_bn, h.mont.N(), h.ctx);
    mod_mul_montgomery(result, x, norm_term, h.mont, h.ctx);
    modular_reduce(h, result);
  }

  friend void normalize(MuHash const &h, openssl::bignum &result, State const &x) {
    openssl::bn_ctx_frame frame(h.ctx);

    long new_r_factor = x.r_factor;

    openssl::bignum const *combined_ptr;

    if (x.removed.is_one()) {
      combined_ptr = &x.added;
    } else {
      auto &temp = frame.get();
      mod_inverse(temp, x.removed, h.mont.N(), h.ctx);
      mod_mul_montgomery(temp, temp, x.added, h.mont, h.ctx);
      // since we do this extra multiplication, we need to add 1 to r_factor
      new_r_factor += 1;
      combined_ptr = &temp;
    }

    normalize(h, result, *combined_ptr, new_r_factor);
  }

  friend void normalize(MuHash const &h, State &result) {
    normalize(h, result.added, result);
    result.removed.set_one();
    result.r_factor = 0;
  }

  friend bool equal(MuHash const &h, State const &a, State const &b) {
    openssl::bn_ctx_frame frame(h.ctx);
    // Check: a.added / a.removed * R^{a.r_factor} == b.added / b.removed * R^{b.r_factor}  mod p
    // i.e. a.added * b.removed * R^{a.r_factor - b.r_factor} == b.added * a.removed  mod p

    auto &lhs = frame.get();
    auto &rhs = frame.get();
    // These montgomery multiplications cancel out, so we don't need to adjust r_factor
    mod_mul_montgomery(lhs, a.added, b.removed, h.mont, h.ctx);
    mod_mul_montgomery(rhs, b.added, a.removed, h.mont, h.ctx);
    normalize(h, lhs, lhs, a.r_factor - b.r_factor);
    modular_reduce(h, rhs);
    return lhs == rhs;
  }

  template <class Data, boost::endian::order order, JBMS_ENABLE_IF(is_byte_range<Data>)>
  friend void assign(MuHash const &h, State &result, endian_wrapper<Data,order> data) {
    assign(result.added, data);
    result.removed.set_one();
    result.r_factor = 0;
  }

  template <class Data, boost::endian::order order, JBMS_ENABLE_IF(is_byte_range<Data>)>
  friend void assign(MuHash const &h, endian_wrapper<Data,order> result, State const &x) {
    openssl::bn_ctx_frame frame(h.ctx);
    auto &normalized = frame.get();
    normalize(h, normalized, x);
    assign(result, normalized);
  }

  friend void hash_element(MuHash const &h, openssl::bignum &result, array_view<void const> x) {
    fill(result,
         h.total_hash_bytes,
         jbms::little_endian([&](uint8_t *buf) { hash::hash_expand(h.hash(), buf, h.num_digests, x); }));
    result.mask_bits(h.num_bits);
    modular_reduce(h, result);

    if (result.is_zero())
      result.set_one();
  }

  friend void add(MuHash const &h, State &state, array_view<void const> x) {
    openssl::bn_ctx_frame frame(h.ctx);
    auto &element_value = frame.get();
    hash_element(h, element_value, x);

    mod_mul_montgomery(state.added, state.added, element_value, h.mont, h.ctx);
    state.r_factor += 1;
  }

  friend void remove(MuHash const &h, State &state, array_view<void const> x) {
    openssl::bn_ctx_frame frame(h.ctx);
    auto &element_value = frame.get();
    hash_element(h, element_value, x);
    mod_mul_montgomery(state.removed, state.removed, element_value, h.mont, h.ctx);
    state.r_factor -= 1;
  }

  friend void add_hash(MuHash const &h, State &state, State const &a) {
    mod_mul_montgomery(state.added, state.added, a.added, h.mont, h.ctx);
    mod_mul_montgomery(state.removed, state.removed, a.removed, h.mont, h.ctx);
    state.r_factor += a.r_factor;
  }

  friend void remove_hash(MuHash const &h, State &state, State const &a) {
    mod_mul_montgomery(state.added, state.added, a.removed, h.mont, h.ctx);
    mod_mul_montgomery(state.removed, state.removed, a.added, h.mont, h.ctx);
    state.r_factor -= a.r_factor;
  }

  // m must be prime
  explicit MuHash(openssl::bignum const &m, Hash const &hash_ = {}) {
    mont.set(m, ctx);
    num_bytes_ = m.num_bytes();
    num_bits = m.num_bits();
    num_digests = jbms::div_ceil(num_bytes(), Hash::digest_bytes);

    total_hash_bytes = num_digests * Hash::digest_bytes;
  }

  Hash const &hash() const { return hash_; }

  size_t num_bytes() const { return num_bytes_; }

private:
  Hash hash_;
  mutable openssl::bn_ctx ctx;
  openssl::bn_mont_ctx mont;
  size_t num_bytes_;
  size_t num_bits;
  size_t num_digests;
  size_t total_hash_bytes;
};


}
}

#endif /* HEADER GUARD */
