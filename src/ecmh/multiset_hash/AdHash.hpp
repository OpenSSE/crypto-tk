#ifndef HEADER_GUARD_e0438bc676205bb1bb9325dbaee01470
#define HEADER_GUARD_e0438bc676205bb1bb9325dbaee01470

#include "openssl/bn.hpp"
#include "./detail/operation_helpers.hpp"
#include "ecmh/utility/division.hpp"
#include "ecmh/hash/hash_expand.hpp"
#include "ecmh/array_view/array_view.hpp"

namespace jbms {
namespace multiset_hash {

template <class Hash_>
struct AdHash;

template <class Hash_>
struct is_multiset_hash<AdHash<Hash_>> : std::true_type {};

// Note: A single AdHash instance is not thread-safe, since it contains a bn_ctx
template <class Hash_>
struct AdHash {
public:
  using Hash = Hash_;

  using State = openssl::bignum;

  friend void initialize(AdHash const &h, State &state) {
    state.set_zero();
  }

  friend void invert(AdHash const &h, State &result, State const &x) {
    sub(result, h.modulus_, x);
  }

  friend bool equal(AdHash const &h, State const &a, State const &b) {
    return a == b;
  }

  template <class Data, boost::endian::order order, JBMS_ENABLE_IF(is_byte_range<Data>)>
  friend void assign(AdHash const &h, State &result, endian_wrapper<Data,order> data) {
    assign(result, data);
    result.mask_bits(h.num_bits_);
  }

  template <class Data, boost::endian::order order, JBMS_ENABLE_IF(is_byte_range<Data>)>
  friend void assign(AdHash const &h, endian_wrapper<Data,order> result, State const &x) {
    assign(result, x);
  }

  friend void hash_element(AdHash const &h, openssl::bignum &result, array_view<void const> x) {
    fill(result,
         h.total_hash_bytes,
         jbms::little_endian([&](uint8_t *buf) { hash::hash_expand(h.hash(), buf, h.num_digests, x); }));
    result.mask_bits(h.num_bits_);
  }

  friend void add(AdHash const &h, State &state, array_view<void const> x) {
    openssl::bn_ctx_frame frame(h.ctx);
    auto &element_value = frame.get();
    hash_element(h, element_value, x);
    add_hash(h, state, element_value);
  }

  friend void remove(AdHash const &h, State &state, array_view<void const> x) {
    openssl::bn_ctx_frame frame(h.ctx);
    auto &element_value = frame.get();
    hash_element(h, element_value, x);
    remove_hash(h, state, element_value);
  }

  friend void add_hash(AdHash const &h, State &state, State const &a) {
    add(state, state, a);
    state.mask_bits(h.num_bits_);
  }

  friend void remove_hash(AdHash const &h, State &state, State const &a) {
    state.set_bit(h.num_bits_);
    sub(state, state, a);
    state.mask_bits(h.num_bits_);
  }

  explicit AdHash(size_t num_bits_, Hash const &hash_ = {})
    : num_bits_(num_bits_), num_bytes_(div_ceil(num_bits_, 8)) {

    num_digests = jbms::div_ceil(num_bytes(), Hash::digest_bytes);

    total_hash_bytes = num_digests * Hash::digest_bytes;
    modulus_.set_zero();
    modulus_.set_bit(num_bits());
  }

  Hash const &hash() const { return hash_; }

  size_t num_bytes() const { return num_bytes_; }
  size_t num_bits() const { return num_bits_; }

private:
  Hash hash_;
  mutable openssl::bn_ctx ctx;
  openssl::bignum modulus_;
  size_t num_bits_;
  size_t num_bytes_;
  size_t num_digests;
  size_t total_hash_bytes;
};


}
}

#endif /* HEADER GUARD */
