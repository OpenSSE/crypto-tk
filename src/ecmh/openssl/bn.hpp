#ifndef HEADER_GUARD_29f4d32dfe1b79d9bff92b3f9359cd94
#define HEADER_GUARD_29f4d32dfe1b79d9bff92b3f9359cd94

#include <openssl/bn.h>
#include "./error.hpp"
#include <boost/endian/conversion.hpp>
#include "ecmh/utility/enable_if.hpp"
#include "ecmh/utility/is_byte.hpp"
#include "ecmh/utility/assign_endian.hpp"
#include "ecmh/utility/division.hpp"
#include <vector>
#include <cctype>

namespace jbms {
namespace openssl {

class bn_ctx {
  BN_CTX *x_;
public:
  bn_ctx() {
    x_ = BN_CTX_new();
    throw_last_error_if(x_ == nullptr);
  }
  explicit bn_ctx(BN_CTX *x_)
    : x_(x_)
  {}

  ~bn_ctx() {
    if (x_)
      BN_CTX_free(x_);
  }

  bn_ctx(bn_ctx &&other) {
    x_ = other.x_;
    other.x_ = nullptr;
  }

  bn_ctx(bn_ctx const &) = delete;
  bn_ctx &operator=(bn_ctx const &) = delete;
  bn_ctx &operator=(bn_ctx &&other) = delete;
  operator BN_CTX *() { return x_; }
  BN_CTX *get() { return x_; }
  void swap(bn_ctx &other) {
    std::swap(x_, other.x_);
  }
};

class bignum;
inline bignum &as_bignum(BIGNUM &bn) {
  return reinterpret_cast<bignum &>(bn);
}
inline bignum const &as_bignum(BIGNUM const &bn) {
  return reinterpret_cast<bignum const &>(bn);
}


struct bn_ctx_frame {
  BN_CTX *ctx;
  bn_ctx_frame(BN_CTX *ctx) : ctx(ctx) {
    BN_CTX_start(ctx);
  }
  bignum &get() {
    auto *result = BN_CTX_get(ctx);
    throw_last_error_if(result == nullptr);
    return as_bignum(*result);
  }

  ~bn_ctx_frame() {
    BN_CTX_end(ctx);
  }
};

class bignum {
  BIGNUM bn_;
public:
  operator BIGNUM *() { return &bn_; }
  operator BIGNUM const *() const { return &bn_; }
  BIGNUM *get() { return &bn_; }
  BIGNUM const *get() const { return &bn_; }
  BIGNUM *operator->() { return &bn_; }
  BIGNUM const *operator->() const { return &bn_; }

  bignum() {
    BN_init(get());
  }
  bignum(unsigned long w) : bignum() {
    *this = w;
  }
  ~bignum() {
    BN_free(get());
  }
  bignum(bignum const &other) : bignum() {
    *this = other;
  }

  bignum(bignum &&other) : bignum() {
    swap(other);
  }

  void swap(bignum &other) {
    BN_swap(get(), other.get());
  }

  bignum &operator=(bignum const &other) {
    BN_copy(get(), other.get());
    return *this;
  }

  bignum &operator=(bignum &&other) {
    swap(other);
    return *this;
  }

  void clear() {
    BN_clear(get());
  }

  int num_bytes() const { return BN_num_bytes(get()); }
  int num_bits() const { return BN_num_bits(get()); }

  bool is_negative() const { return BN_is_negative(get()); }
  void set_negative(int n) { BN_set_negative(get(), n); }

  static bignum const &one() { return as_bignum(*BN_value_one()); }
  bignum &operator=(unsigned long w) {
    set_word(w);
    return *this;
  }
  bignum &operator=(long w) {
    if (w >= 0)
      set_word((unsigned long)w);
    else {
      set_word((unsigned long)-w);
      set_negative(true);
    }
    return *this;
  }

  void set_word(unsigned long w) {
    throw_last_error_if(BN_set_word(get(), w) == 0);
  }

  void set_zero() {
    throw_last_error_if(BN_zero(get()) == 0);
  }
  void set_one() {
    throw_last_error_if(BN_one(get()) == 0);
  }
  void set_bit(int n) {
    throw_last_error_if(BN_set_bit(get(), n) == 0);
  }

  // Returns true if number has at least n bits
  bool clear_bit(int n) {
    return (BN_clear_bit(get(), n) == 1);
  }


  bool is_bit_set(int n) const {
    return BN_is_bit_set(get(), n);
  }

  void set_bit(int n, bool value) {
    if (value)
      set_bit(n);
    else
      clear_bit(n);
  }

  // Returns true if the number was longer than n bits
  bool mask_bits(int n) {
    return BN_mask_bits(get(), n) == 1;
  }

  bool is_zero() const {
    return BN_is_zero(get());
  }

  bool is_one() const {
    return BN_is_one(get());
  }

  bool is_word(unsigned long w) const {
    return BN_is_word(get(), w);
  }

  bool is_odd() const {
    return BN_is_odd(get());
  }

  void set_from_hex(const char *x) {
    BIGNUM *ptr = get();
    throw_last_error_if(BN_hex2bn(&ptr, x) == 0);
  }
  void set_from_hex(std::string const &x) {
    set_from_hex(x.c_str());
  }

  std::string to_hex() const {
    char *temp = BN_bn2hex(get());
    throw_last_error_if(temp == nullptr);
    std::string result(temp);
    OPENSSL_free(temp);
    return result;
  }

  // Returns lowercase hex representation without leading zeros
  std::string to_canonical_hex() const {
    // Remove leading zeros
    std::string temp = to_hex();
    size_t i = 0;
    for (; i + 1 < temp.size(); ++i) {
      if (temp[i] != '0')
        break;
    }
    // Make lowercase for consistency
    for (auto &x : temp)
      x = std::tolower(x);
    return temp.substr(i);
  }

  std::string to_dec() const {
    char *temp = BN_bn2dec(get());
    throw_last_error_if(temp == nullptr);
    std::string result(temp);
    OPENSSL_free(temp);
    return result;
  }

  void set_from_dec(const char *x) {
    BIGNUM *ptr = get();
    throw_last_error_if(BN_dec2bn(&ptr, x) == 0);
  }
  void set_from_dec(std::string const &x) {
    set_from_dec(x.c_str());
  }

  bignum &operator+=(unsigned long w) {
    throw_last_error_if(BN_add_word(get(), w) == 0);
    return *this;
  }

  bignum &operator-=(unsigned long w) {
    throw_last_error_if(BN_sub_word(get(), w) == 0);
    return *this;
  }

  bignum &operator*=(unsigned long w) {
    throw_last_error_if(BN_mul_word(get(), w) == 0);
    return *this;
  }
};

/**
 * Invokes wrapper.data on a uint8_t array of length num_bytes
 *
 * x is set to be the contents of that buffer, interpreted as order endianness
 **/
template <class Func, boost::endian::order order,
          JBMS_ENABLE_IF_EXPR(std::declval<Func>()(std::declval<uint8_t *>()))>
inline void fill(bignum &x, size_t num_bytes, endian_wrapper<Func,order> wrapper) {
  x.set_zero();
  size_t num_words = jbms::div_ceil(num_bytes, sizeof(BN_ULONG));

  // ensure there is enough space
  bn_wexpand(x.get(), num_words);
  x.get()->top = num_words;

  // set final word to 0 since it might not be completely overwritten by the function
  if (num_words > 0)
    x.get()->d[num_words-1] = 0;

  // call function
  auto buf = (uint8_t *)x.get()->d;
  wrapper.data(buf);

  // reverse bytes if big endian
  if (order == boost::endian::order::big)
    std::reverse(buf, buf + num_bytes);

  // convert endian (no-op if order == little endian)
  for (size_t i = 0; i < num_words; ++i) {
    boost::endian::little_endian(x.get()->d[i]);
  }

  bn_fix_top(x.get());
}


/**
 *  Interoperability with assign_endian functionality.
 **/

// result must have size == x.num_bytes
template <class Dest, JBMS_ENABLE_IF(is_byte_range<Dest>)>
inline void assign(endian_wrapper<Dest,boost::endian::order::big> wrapper,
                   bignum const &x) {
  wrapper.ensure_size_equals(x.num_bytes());

  // always writes exactly x.num_bytes(), doesn't produce errors
  BN_bn2bin(x.get(), wrapper.data.data());
}

// result must have size == x.num_bytes
template <class Dest, JBMS_ENABLE_IF(is_byte_range<Dest>)>
inline void assign(endian_wrapper<Dest,boost::endian::order::little> wrapper,
                   bignum const &x) {
  wrapper.ensure_size_equals(x.num_bytes());

  // always writes exactly x.num_bytes(), doesn't produce errors
  BN_bn2bin(x.get(), wrapper.data.data());

  // OpenSSL doesn't provide access to little endian representation directly, so we just reverse big endian output
  std::reverse(wrapper.data.begin(), wrapper.data.end());
}

template <class Source, boost::endian::order order, JBMS_ENABLE_IF(is_byte_range<Source>)>
void assign(bignum &x, endian_wrapper<Source, order> source) {
  fill(x,
       source.data.size(),
       jbms::make_endian_wrapper<order>([&](uint8_t *buf) { memcpy(buf, source.data.data(), source.data.size()); }));
}

// r = a + b
// r may alias a or b
inline void add(bignum &r, const bignum &a, const bignum &b) {
  throw_last_error_if(BN_add(r.get(), a.get(), b.get()) == 0);
}

// r = a - b
// r may alias a or b
inline void sub(bignum &r, const bignum &a, const bignum &b) {
  throw_last_error_if(BN_sub(r.get(), a.get(), b.get()) == 0);
}

// r = a * b
// r may alias a or b
inline void mul(bignum &r, const bignum &a, const bignum &b, BN_CTX *ctx) {
  throw_last_error_if(BN_mul(r.get(), a.get(), b.get(), ctx) == 0);
}


// r = a * b
// r may alias a
inline void sqr(bignum &r, const bignum &a, BN_CTX *ctx) {
  throw_last_error_if(BN_sqr(r.get(), a.get(), ctx) == 0);
}

// either of dv or rem can be nullptr
inline void div(BIGNUM *dv, BIGNUM *rem, const bignum &a, const bignum &d, BN_CTX *ctx) {
  throw_last_error_if(BN_div(dv, rem, a.get(), d.get(), ctx) == 0);
}

inline void mod(bignum &rem, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx) {
  throw_last_error_if(BN_mod(rem.get(), a, m, ctx) == 0);
}

inline void nnmod(bignum &r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx) {
  throw_last_error_if(BN_nnmod(r.get(), a, m, ctx) == 0);
}

inline void mod_add(bignum &r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx) {
  throw_last_error_if(BN_mod_add(r.get(), a, b, m, ctx) == 0);
}

inline void mod_sub(bignum &r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx) {
  throw_last_error_if(BN_mod_sub(r.get(), a, b, m, ctx) == 0);
}

inline void mod_mul(bignum &r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx) {
  throw_last_error_if(BN_mod_mul(r.get(), a, b, m, ctx) == 0);
}

inline void mod_sqr(bignum &r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx) {
  throw_last_error_if(BN_mod_sqr(r.get(), a, m, ctx) == 0);
}

inline void exp(bignum &r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx) {
  throw_last_error_if(BN_exp(r.get(), a, p, ctx) == 0);
}

inline void mod_exp(bignum &r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx) {
  throw_last_error_if(BN_mod_exp(r.get(), a, p, m, ctx) == 0);
}

/* r may alias a */
inline void mod_inverse(bignum &r, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx) {
  throw_last_error_if(BN_mod_inverse(r.get(), a, n, ctx) == 0);
}

inline void gcd(bignum &r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx) {
  throw_last_error_if(BN_gcd(r.get(), a, b, ctx) == 0);
}

inline int compare(bignum const &a, bignum const &b) {
  return BN_cmp(a, b);
}

inline int abs_compare(bignum const &a, bignum const &b) {
  return BN_ucmp(a, b);
}

#define OPENSSL_PP_BIGNUM_COMPARE(op)                                               \
  inline bool operator op(bignum const &a, bignum const &b) { return compare(a, b) op 0; } \
/**/

OPENSSL_PP_BIGNUM_COMPARE(==)
OPENSSL_PP_BIGNUM_COMPARE(!=)
OPENSSL_PP_BIGNUM_COMPARE(<)
OPENSSL_PP_BIGNUM_COMPARE(<=)
OPENSSL_PP_BIGNUM_COMPARE(>)
OPENSSL_PP_BIGNUM_COMPARE(>=)

#undef OPENSSL_PP_BIGNUM_COMPARE

inline bool operator==(bignum const &a, unsigned long w) { return a.is_word(w); }
inline bool operator==(unsigned long w, bignum const &a) { return a.is_word(w); }
inline bool operator!=(bignum const &a, unsigned long w) { return !(a == w); }
inline bool operator!=(unsigned long w, bignum const &a) { return !(a == w); }

// We want to be able to use bignum interchangeable with BIGNUM
static_assert(sizeof(bignum) == sizeof(BIGNUM), "");

class bn_recp_ctx {
  BN_RECP_CTX x_;
public:
  bn_recp_ctx() {
    BN_RECP_CTX_init(&x_);
  }
  ~bn_recp_ctx() {
    BN_RECP_CTX_free(&x_);
  }

  bn_recp_ctx(bn_recp_ctx const &other) : bn_recp_ctx() {
    *this = other;
  }
  bn_recp_ctx(bn_recp_ctx &&other) : bn_recp_ctx() {
    swap(other);
  }

  bn_recp_ctx(const BIGNUM *m, BN_CTX *ctx) : bn_recp_ctx() {
    set(m, ctx);
  }

  bn_recp_ctx &operator=(bn_recp_ctx const &other) {
    x_.num_bits = other->num_bits;
    x_.shift = other->shift;
    x_.flags = other->flags;
    divisor() = other.divisor();
    reciprocal() = other.reciprocal();
    return *this;
  }

  void swap(bn_recp_ctx &other) {
    std::swap(x_.num_bits, other->num_bits);
    std::swap(x_.shift, other->shift);
    std::swap(x_.flags, other->flags);
    divisor().swap(other.divisor());
    reciprocal().swap(other.reciprocal());
  }

  bn_recp_ctx &operator=(bn_recp_ctx &&other) {
    swap(other);
    return *this;
  }

  void set(const BIGNUM *m, BN_CTX *ctx) {
    throw_last_error_if(BN_RECP_CTX_set(get(), m, ctx) == 0);
  }

  operator BN_RECP_CTX *() { return &x_; }
  BN_RECP_CTX *get() { return &x_; }

  BN_RECP_CTX *operator->() { return &x_; }
  BN_RECP_CTX const *operator->() const { return &x_; }

  bignum &divisor() { return as_bignum(x_.N); }
  bignum const &divisor() const { return as_bignum(x_.N); }

  bignum &reciprocal() { return as_bignum(x_.Nr); }
  bignum const &reciprocal() const { return as_bignum(x_.Nr); }
};
static_assert(sizeof(bn_recp_ctx) == sizeof(BN_RECP_CTX),"");

inline void div_recp(BIGNUM *dv, BIGNUM *rem, bignum const &a, BN_RECP_CTX *recp, BN_CTX *ctx) {
  throw_last_error_if(BN_div_recp(dv, rem, a.get(), recp, ctx) == 0);
}

inline void mod_mul_reciprocal(bignum &r, BIGNUM const *a, BIGNUM const *b, BN_RECP_CTX *recp, BN_CTX *ctx) {
  throw_last_error_if(BN_mod_mul_reciprocal(r.get(), a, b, recp, ctx) == 0);
}

class bn_mont_ctx {
  BN_MONT_CTX ctx_;
public:
  BN_MONT_CTX *get() { return &ctx_; }
  BN_MONT_CTX const *get() const { return &ctx_; }
  operator BN_MONT_CTX * () { return &ctx_; }
  operator BN_MONT_CTX const * () const { return &ctx_; }
  BN_MONT_CTX *operator->() { return &ctx_; }
  BN_MONT_CTX const *operator->() const { return &ctx_; }

  bn_mont_ctx() {
    BN_MONT_CTX_init(get());
  }
  ~bn_mont_ctx() {
    BN_MONT_CTX_free(get());
  }
  bignum const &RR() const { return as_bignum(ctx_.RR); }
  bignum &RR() { return as_bignum(ctx_.RR); }

  // The modulus
  bignum const &N() const { return as_bignum(ctx_.N); }
  bignum &N() { return as_bignum(ctx_.N); }

  bignum const &Ni() const { return as_bignum(ctx_.Ni); }
  bignum &Ni() { return as_bignum(ctx_.Ni); }

  bn_mont_ctx(bn_mont_ctx const &other) : bn_mont_ctx() {
    *this = other;
  }

  bn_mont_ctx(bn_mont_ctx &&other) : bn_mont_ctx() {
    swap(other);
  }

  bn_mont_ctx(BIGNUM const *m, BN_CTX *ctx) {
    set(m, ctx);
  }

  bn_mont_ctx &operator=(bn_mont_ctx const &other) {
    throw_last_error_if(BN_MONT_CTX_copy(get(), const_cast<BN_MONT_CTX *>(other.get())) == nullptr);
    return *this;
  }

  void swap(bn_mont_ctx &other) {
    std::swap(ctx_.ri, other->ri);
    RR().swap(other.RR());
    N().swap(other.N());
    Ni().swap(other.Ni());
    std::swap(ctx_.n0, other->n0);
    std::swap(ctx_.flags, other->flags);
  }
  bn_mont_ctx &operator=(bn_mont_ctx &&other) {
    swap(other);
    return *this;
  }

  void set(const BIGNUM *m, BN_CTX *ctx) {
    throw_last_error_if(BN_MONT_CTX_set(get(), m, ctx) == 0);
  }

};
static_assert(sizeof(bn_mont_ctx) == sizeof(BN_MONT_CTX), "");

inline void from_montgomery(bignum &r, BIGNUM const *a, BN_MONT_CTX const *mont, BN_CTX *ctx) {
  throw_last_error_if(BN_from_montgomery(r.get(), a, const_cast<BN_MONT_CTX *>(mont), ctx) == 0);
}

inline void to_montgomery(bignum &r, BIGNUM const *a, BN_MONT_CTX const *mont, BN_CTX *ctx) {
  throw_last_error_if(BN_to_montgomery(r.get(), a, const_cast<BN_MONT_CTX *>(mont), ctx) == 0);
}

// r may alias a
// a may alias b
inline void mod_mul_montgomery(bignum &r, BIGNUM const *a, BIGNUM const *b, BN_MONT_CTX const *mont, BN_CTX *ctx) {
  throw_last_error_if(BN_mod_mul_montgomery(r.get(), a, b, const_cast<BN_MONT_CTX *>(mont), ctx) == 0);
}


#ifndef OPENSSL_NO_EC2M

// For all of the variants that accept a const int p[] argument, the modulus p is specified as a (-1)-terminated, decreasing list of 1 coefficients.
// The array variants are more efficient because the non-array variants are mapped by OpenSSL to the array variants.

// r, a, b are GF(2^m) field elements
// r = a + b
// r may alias a or b
inline void GF2m_add(bignum &r, BIGNUM const *a, BIGNUM const *b) {
  throw_last_error_if(BN_GF2m_add(r.get(), a, b) == 0);
}

// r, a, p are GF(2^m) field elements
// r = a mod p
// r may alias a.
inline void GF2m_mod(bignum &r, BIGNUM const *a, BIGNUM const *p) {
  throw_last_error_if(BN_GF2m_mod(r.get(), a, p) == 0);
}
inline void GF2m_mod(bignum &r, BIGNUM const *a, const int p[]) {
  throw_last_error_if(BN_GF2m_mod_arr(r.get(), a, p) == 0);
}


// r, a, b, p are GF(2^m) field elements
// r = (a * b) mod p
// r may alias a or b
// a may alias b
inline void GF2m_mod_mul(bignum &r, BIGNUM const *a, BIGNUM const *b, BIGNUM const *p, BN_CTX *ctx) {
  throw_last_error_if(BN_GF2m_mod_mul(r.get(), a, b, p, ctx) == 0);
}
inline void GF2m_mod_mul(bignum &r, BIGNUM const *a, BIGNUM const *b, const int p[], BN_CTX *ctx) {
  throw_last_error_if(BN_GF2m_mod_mul_arr(r.get(), a, b, p, ctx) == 0);
}

// r, a, p are GF(2^m) field elements
// r = (a * a) mod p
// r may alias a
inline void GF2m_mod_sqr(bignum &r, BIGNUM const *a, BIGNUM const *p, BN_CTX *ctx) {
  throw_last_error_if(BN_GF2m_mod_sqr(r.get(), a, p, ctx) == 0);
}
inline void GF2m_mod_sqr(bignum &r, BIGNUM const *a, const int p[], BN_CTX *ctx) {
  throw_last_error_if(BN_GF2m_mod_sqr_arr(r.get(), a, p, ctx) == 0);
}

// r, a, p are GF(2^m) field elements
// r = a^{-1} mod p
// r may alias a
inline void GF2m_mod_inv(bignum &r, BIGNUM const *a, BIGNUM const *p, BN_CTX *ctx) {
  throw_last_error_if(BN_GF2m_mod_inv(r.get(), a, p, ctx) == 0);
}
inline void GF2m_mod_inv(bignum &r, BIGNUM const *a, const int p[], BN_CTX *ctx) {
  throw_last_error_if(BN_GF2m_mod_inv_arr(r.get(), a, p, ctx) == 0);
}

// r, a, b, p are GF(2^m) field elements
// r = (a / b) mod p
// r may alias a or b
// a may alias b
inline void GF2m_mod_div(bignum &r, BIGNUM const *a, BIGNUM const *b, BIGNUM const *p, BN_CTX *ctx) {
  throw_last_error_if(BN_GF2m_mod_div(r.get(), a, b, p, ctx) == 0);
}
inline void GF2m_mod_div(bignum &r, BIGNUM const *a, BIGNUM const *b, const int p[], BN_CTX *ctx) {
  throw_last_error_if(BN_GF2m_mod_div_arr(r.get(), a, b, p, ctx) == 0);
}

// r, a are GF(2^m) field elements
// Computes r such that r^2 = a
// r may alias a
inline void GF2m_mod_sqrt(bignum &r, BIGNUM const *a, BIGNUM const *p, BN_CTX *ctx) {
  throw_last_error_if(BN_GF2m_mod_sqrt(r.get(), a, p, ctx) == 0);
}
inline void GF2m_mod_sqrt(bignum &r, BIGNUM const *a, const int p[], BN_CTX *ctx) {
  throw_last_error_if(BN_GF2m_mod_sqrt_arr(r.get(), a, p, ctx) == 0);
}

// r, a are GF(2^m) field elements
// b is an integer
// r = a^b mod p
// r may alias a
inline void GF2m_mod_exp(bignum &r, BIGNUM const *a, BIGNUM const *b, BIGNUM const *p, BN_CTX *ctx) {
  throw_last_error_if(BN_GF2m_mod_exp(r.get(), a, b, p, ctx) == 0);
}
inline void GF2m_mod_exp(bignum &r, BIGNUM const *a, BIGNUM const *b, const int p[], BN_CTX *ctx) {
  throw_last_error_if(BN_GF2m_mod_exp_arr(r.get(), a, b, p, ctx) == 0);
}


// r, a, p are GF(2^m) field elements
// r^2 + r = a mod p
// r may alias a
// Returns 0 if no such r exists.
inline void GF2m_mod_solve_quad(bignum &r, BIGNUM const *a, BIGNUM const *p, BN_CTX *ctx) {
  throw_last_error_if(BN_GF2m_mod_solve_quad(r.get(), a, p, ctx) == 0);
}
inline void GF2m_mod_solve_quad(bignum &r, BIGNUM const *a, const int p[], BN_CTX *ctx) {
  throw_last_error_if(BN_GF2m_mod_solve_quad_arr(r.get(), a, p, ctx) == 0);
}

// p is a (-1)-terminated array of coefficients
inline void GF2m_arr2poly(const int p[], bignum &a) {
  throw_last_error_if(BN_GF2m_arr2poly(p, a.get()) == 0);
}

// Sets p to be a (-1)-terminated array of 1 coefficients
// Only up to max values in p are set (the -1 will only be appended if there is sufficient space)
// Returns the size of p that would be required to avoid truncation.
inline int GF2m_poly2arr(bignum const &a, int p[], int max) {
  return BN_GF2m_poly2arr(a.get(), p, max);
}

inline std::vector<int> GF2m_poly2arr(bignum const &a) {
  std::vector<int> result;
  int max = GF2m_poly2arr(a, result.data(), 0);
  result.resize(max);
  GF2m_poly2arr(a, result.data(), max);
  return result;
}

#endif // end if !defined(OPENSSL_NO_EC2M)


/**
 * If top equals:
 *  -1 :  top bit is random (i.e. can be 0)
 *   0 :  top bit will be 1
 *   1 :  top two bits will be 1
 *
 * If bottom equals:
 *   1  : number is odd (bottom bit is 1)
 *   0  : bottom bit is random (i.e. can be 0)
 **/
inline void rand(bignum &r, int bits, int top, int bottom) {
  throw_last_error_if(BN_rand(r.get(), bits, top, bottom) == 0);
}

// Same as rand, but not cryptographically secure
inline void pseudo_rand(bignum &r, int bits, int top, int bottom) {
  throw_last_error_if(BN_pseudo_rand(r.get(), bits, top, bottom) == 0);
}

// // Post-condition: 0 <= r < range
// inline void rand_range(bignum &r, bignum const &range) {
//   throw_last_error_if(BN_rand_range(r.get(), range.get()) == 0);
// }
// // Same as rand_range, but not cryptographically secure
// inline void pseudo_rand_range(bignum &r, bignum const &range) {
//   throw_last_error_if(BN_pseudo_rand_range(r.get(), range.get()) == 0);
// }


}
}

#endif /* HEADER GUARD */
