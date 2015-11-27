#ifndef HEADER_GUARD_d95be3b703d812f4d24e44aa5fb95213
#define HEADER_GUARD_d95be3b703d812f4d24e44aa5fb95213

/**
 * Implementation of Field concept using OpenSSL GF2m functions
 *
 * This is primarily intended for testing purposes.
 **/

#include "openssl/bn.hpp"
#include "./detail/field_operation_helpers.hpp"
#include "./generic_trace.hpp"
#include "./generic_half_trace.hpp"
#include "ecmh/utility/assign_endian.hpp"
#include "ecmh/utility/division.hpp"
#include "ecmh/utility/is_byte.hpp"
#include "ecmh/array_view/array_view.hpp"
#include <boost/range/functions.hpp>

namespace jbms {
namespace binary_field {

struct GF2m;

template <>
struct is_field<GF2m> : std::true_type {};

struct GF2m {
  // (-1)-terminated decreasing array of 1 coefficients in modulus polynomial
  // first element is degree of field
  std::vector<int> modulus;
  mutable jbms::openssl::bn_ctx ctx;
  size_t first_trace_bit = 0;

  size_t degree() const { return (size_t)modulus.front(); }
  size_t num_bytes() const { return div_ceil(degree(), 8); }

  using Element = jbms::openssl::bignum;
  using DoubleElement = Element;

  GF2m(std::vector<int> const &modulus)
    : modulus(modulus) {
    if (modulus.empty())
      throw std::invalid_argument("empty modulus");
    // verify that modulus is a decreasing positive sequence
    for (size_t i = 1; i < modulus.size(); ++i) {
      if (modulus[i] < 0 || modulus[i] >= modulus[i-1])
        throw std::invalid_argument("modulus must be a positive, decreasing sequence");
    }
    this->modulus.push_back(-1);

    // Determine first trace bit.
    for (size_t i = 0; i < degree(); ++i) {
      Element x;
      x.set_bit((int)i, true);
      if (trace(*this, x)) {
        first_trace_bit = i;
        break;
      }
    }
  }
  GF2m(GF2m const &other)
    : modulus(other.modulus), first_trace_bit(other.first_trace_bit)
  {}
  GF2m(GF2m &&other) = default;
  GF2m &operator=(GF2m const &other) {
    modulus = other.modulus;
    first_trace_bit = other.first_trace_bit;
    return *this;
  }
  GF2m &operator=(GF2m &&other) = default;

  friend void assign(GF2m const &F, Element &x, bool value) {
    x = (unsigned long)value;
  }

  friend void set_zero(GF2m const &F, Element &x) {
    x.set_zero();
  }

  friend void set_one(GF2m const &F, Element &x) {
    x.set_one();
  }

  friend bool is_zero(GF2m const &F, Element const &x) {
    return x.is_zero();
  }

  friend bool is_one(GF2m const &F, Element const &x) {
    return x.is_one();
  }

  friend bool equal(GF2m const &F, Element const &a, Element const &b) {
    return abs_compare(a, b) == 0;
  }

  friend void add(GF2m const &F, Element &x, Element const &a, Element const &b) {
    GF2m_add(x, a, b);
  }

  friend void multiply(GF2m const &F, Element &z, Element const &a, Element const &b) {
    GF2m_mod_mul(z, a, b, F.modulus.data(), F.ctx);
  }

  friend void square(GF2m const &F, Element &z, Element const &a) {
    GF2m_mod_sqr(z, a, F.modulus.data(), F.ctx);
  }

  friend void reduce_after_multiply(GF2m const &F, Element &z, Element const &a) {
    GF2m_mod(z, a, F.modulus.data());
  }

  friend void multiply_no_reduce(GF2m const &F, Element &z, Element const &a, Element const &b) {
    // Same as multiply.  OpenSSL does not provide an interface for direct polynomial multiplication.
    multiply(F, z, a, b);
  }

  friend void square_no_reduce(GF2m const &F, Element &z, Element const &a) {
    // Same as square.  OpenSSL does not provide an interface for direct polynomial squaring.
    square(F, z, a);
  }

  friend void invert(GF2m const &F, Element &z, Element const &a) {
    GF2m_mod_inv(z, a, F.modulus.data(), F.ctx);
  }

  friend bool trace(GF2m const &F, Element const &a) {
    return generic_trace(F, a);
  }

  // Only valid if F.degree() % 2 == 1
  friend void half_trace(GF2m const &F, Element &result, Element const &a) {
    if (F.degree() % 2 == 0)
      throw std::invalid_argument("half_trace not defined for even-degree fields");
    return generic_half_trace(F, result, a);
  }

  friend void sqrt(GF2m const &F, Element &result, Element const &a) {
    GF2m_mod_sqrt(result, a, F.modulus.data(), F.ctx);
  }

  friend void solve_quadratic(GF2m const &F, Element &result, Element const &a) {
    GF2m_mod_solve_quad(result, a, F.modulus.data(), F.ctx);
  }

  friend std::string to_hex(GF2m const &F, Element const &a) {
    return a.to_canonical_hex();
  }

  friend void assign_from_hex(GF2m const &F, Element &a, std::string const &hex_string) {
    a.set_from_hex(hex_string);
  }

  template <class Range>
  friend void assign_from_hex(GF2m const &F, Element &a, Range const &range) {
    assign_from_hex(F, a, std::string(boost::begin(range), boost::end(range)));
  }

  template <class Data, boost::endian::order order, JBMS_ENABLE_IF(is_byte_range<Data>)>
  friend void assign(GF2m const &F, Element &a, endian_wrapper<Data,order> x) {
    a = x.operator Element();
    a.mask_bits(F.degree());
  }

  template <class Data, boost::endian::order order, JBMS_ENABLE_IF(is_byte_range<Data>)>
  friend void assign(GF2m const &F, endian_wrapper<Data,order> x, Element const &a) {
    x.ensure_size_equals(F.num_bytes());

    auto v = jbms::make_view(x.data);


    if ((size_t)a.num_bytes() < (size_t)F.num_bytes()) {
      // the underlying bignum may actually have fewer bytes that F.num_bytes()
      std::fill(x.data.begin(), x.data.end(), 0);

      if (order == boost::endian::order::big)
        v = v.unchecked_slice_after(F.num_bytes() - a.num_bytes());
      else
        v = v.unchecked_slice_before(a.num_bytes());
    }

    make_endian_wrapper<order>(v) = a;
  }

  friend bool get_bit(GF2m const &F, Element const &a, size_t i) {
    return a.is_bit_set((int)i);
  }

  friend void set_bit(GF2m const &F, Element &a, size_t i, bool value) {
    a.set_bit((int)i, value);
  }

// 
//   // uses OpenSSL random number generation
//   friend void pseudo_rand(GF2m const &F, Element &x) {
//     pseudo_rand(x, F.degree(), -1, 0);
//   }
//
//   friend void pseudo_rand_double(GF2m const &F, Element &x) {
//     pseudo_rand(x, F.degree()*2-1, -1, 0);
//   }
//
//
//   friend Element pseudo_rand_element(GF2m const &F) {
//     Element x;
//     pseudo_rand(F, x);
//     return x;
//   }
//
//   friend Element pseudo_rand_double_element(GF2m const &F) {
//     Element x;
//     pseudo_rand_double(F, x);
//     return x;
//   }
//
//
//   // uses OpenSSL random number generation
//   friend void rand(GF2m const &F, Element &x) {
//     rand(x, F.degree(), -1, 0);
//   }
//
//   friend void rand_double(GF2m const &F, Element &x) {
//     rand(x, F.degree()*2-1, -1, 0);
//   }
//
//
//   friend Element rand_element(GF2m const &F) {
//     Element x;
//     rand(F, x);
//     return x;
//   }
//
//   friend Element rand_double_element(GF2m const &F) {
//     Element x;
//     rand_double(F, x);
//     return x;
//   }
//
//   friend void assign_random(GF2m const &F, Element &x) { rand(F, x); }

  friend void set_trace_zero(GF2m const &F, Element &x) {
    x.set_bit(F.first_trace_bit, x.is_bit_set(F.first_trace_bit) ^ trace(F, x));
  }

  friend void set_in_qs_image(GF2m const &F, Element &x) {
    // Only works if (D.degree() % 2) == 1.
    set_trace_zero(F, x);
  }
};

}
}

#endif /* HEADER GUARD */
