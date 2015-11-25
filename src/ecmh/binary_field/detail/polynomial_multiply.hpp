#ifndef HEADER_GUARD_657ca6020b0e238a010fa0d7ef18ad1d
#define HEADER_GUARD_657ca6020b0e238a010fa0d7ef18ad1d

/**
 * The poly_{multiply,square}_impl_64 routines below are subject to the following notice:
 **/

/*********************************************************************************************
 *	EC2M XMM Library
 *
 * This library provides arithmetic in GF(2^m) for m € {163, 193, 233, 239, 283, 409, 571}
 * for the use with elliptic curve cryptography, utilizing Intels vector instructions AVX via
 * compiler intrinsics. For more information about the library please see [1]. The masking
 * scheme has been slightly improved to reduce the number of instructions.
 *
 * [1] M. Bluhm, S. Gueron, 'Fast Software Implementation of Binary Elliptic Curve Cryptography',
 *     2013, https://eprint.iacr.org/2013/741
 *********************************************************************************************/


/*********************************************************************************************
 * Copyright (C) 2014, Manuel Bluhm
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *********************************************************************************************/


#include "./polynomial_base.hpp"
#include "./limb_ops.hpp"

// http://rt.openssl.org/Ticket/Display.html?id=3117&user=guest&pass=guest
//

namespace jbms {
namespace binary_field {

namespace detail {

// integral_constant parameter specifies number of 64-bit input words


/* Simple 2-term Karatsuba multiplication. */
inline void poly_multiply_impl_64(std::integral_constant<size_t, 2>, limb_t z[2], limb_t const a[1], limb_t const b[1]) {
  limb_t x[4];

  /* Prepare temporary operands */
  x[0] = SHR128<8>(a[0]);
  x[1] = XOR(a[0], x[0]);
  x[2] = SHR128<8>(b[0]);
  x[3] = XOR(b[0], x[2]);

  /* Do multiplications */
  z[0] = poly_mul_vec<0,0>(a[0], b[0]);
  z[1] = poly_mul_vec<1,1>(a[0], b[0]);
  x[0] = poly_mul_vec<0,0>(x[1], x[3]);

  x[1] = XOR(z[0], z[1]);
  x[0] = XOR(x[0], x[1]);

  x[1] = SHL128<8>(x[0]);
  x[2] = SHR128<8>(x[0]);

  z[0] = XOR(z[0], x[1]);
  z[1] = XOR(z[1], x[2]);
}

/* Simple 3-term Karatsuba multiplication. */
inline void poly_multiply_impl_64(std::integral_constant<size_t, 3>, limb_t z[3], const limb_t a[2], const limb_t b[2]) {
  limb_t m[3], t[4];

  /* Prepare temporary operands */
  t[0] = ALIGNR<8>(a[1], a[0]);
  t[1] = XOR(a[0], t[0]);
  t[2] = ALIGNR<8>(b[1], b[0]);
  t[3] = XOR(b[0], t[2]);
  t[0] = XOR(a[0], a[1]);
  t[2] = XOR(b[0], b[1]);

  /* Do multiplications */
  z[0] = poly_mul_vec<0,0>(a[0], b[0]);
  z[1] = poly_mul_vec<1,1>(a[0], b[0]);
  z[2] = poly_mul_vec<0,0>(a[1], b[1]);
  m[0] = poly_mul_vec<0,0>(t[1], t[3]);
  m[1] = poly_mul_vec<0,0>(t[2], t[0]);
  m[2] = poly_mul_vec<1,1>(t[1], t[3]);

  m[0] = XOR(m[0], z[0]);
  m[0] = XOR(m[0], z[1]);
  m[1] = XOR(m[1], z[0]);
  m[1] = XOR(m[1], z[2]);
  m[2] = XOR(m[2], z[1]);
  m[2] = XOR(m[2], z[2]);

  t[0] = SHL128<8>(m[0]);
  z[0] = XOR(z[0], t[0]);
  t[1] = ALIGNR<8>(m[2], m[0]);
  z[1] = XOR(z[1], t[1]);
  z[1] = XOR(z[1], m[1]);
  t[3] = SHR128<8>(m[2]);
  z[2] = XOR(z[2], t[3]);
}

/* Recursive 4-term Karatsuba multiplication. */
inline void poly_multiply_impl_64(std::integral_constant<size_t, 4>, limb_t z[4], const limb_t a[2], const limb_t b[2]) {
  limb_t t[4];

  /* Do multiplication */
  poly_multiply_impl_64(std::integral_constant<size_t, 2>{}, z, &a[0], &b[0]);
  poly_multiply_impl_64(std::integral_constant<size_t, 2>{}, z + 2, &a[1], &b[1]);

  t[2] = XOR(a[0], a[1]);
  t[3] = XOR(b[0], b[1]);
  poly_multiply_impl_64(std::integral_constant<size_t, 2>{}, t, &t[2], &t[3]);

  t[0] = XOR(t[0], z[0]);
  t[0] = XOR(t[0], z[2]);
  t[1] = XOR(t[1], z[1]);
  t[1] = XOR(t[1], z[3]);
  z[1] = XOR(z[1], t[0]);
  z[2] = XOR(z[2], t[1]);
}

/* Advanced 5-term Karatsuba multiplication as suggested in "Five, Six, and Seven-Term
 * Karatsuba-Like Formulae" by Peter L. Montgomery, requiring 13 multiplications.
 */
inline void poly_multiply_impl_64(std::integral_constant<size_t, 5>, limb_t z[5], const limb_t a[3], const limb_t b[3]) {
  limb_t m[13], t[13];

  /* Prepare temporary operands */
  t[0] = UNPACKLO64(a[0], b[0]);
  t[1] = UNPACKHI64(a[0], b[0]);
  t[2] = UNPACKLO64(a[1], b[1]);
  t[3] = UNPACKHI64(a[1], b[1]);
  t[4] = UNPACKLO64(a[2], b[2]);

  t[5] = XOR(t[0], t[1]);
  t[6] = XOR(t[0], t[2]);
  t[7] = XOR(t[2], t[4]);
  t[8] = XOR(t[3], t[4]);
  t[9] = XOR(t[3], t[6]);
  t[10] = XOR(t[1], t[7]);
  t[11] = XOR(t[5], t[8]);
  t[12] = XOR(t[2], t[11]);

  /* Do multiplications */
  m[0] = poly_mul_vec<0,1>(t[0], t[0]);
  m[1] = poly_mul_vec<0,1>(t[1], t[1]);
  m[2] = poly_mul_vec<0,1>(t[2], t[2]);
  m[3] = poly_mul_vec<0,1>(t[3], t[3]);
  m[4] = poly_mul_vec<0,1>(t[4], t[4]);
  m[5] = poly_mul_vec<0,1>(t[5], t[5]);
  m[6] = poly_mul_vec<0,1>(t[6], t[6]);
  m[7] = poly_mul_vec<0,1>(t[7], t[7]);
  m[8] = poly_mul_vec<0,1>(t[8], t[8]);
  m[9] = poly_mul_vec<0,1>(t[9], t[9]);
  m[10] = poly_mul_vec<0,1>(t[10], t[10]);
  m[11] = poly_mul_vec<0,1>(t[11], t[11]);
  m[12] = poly_mul_vec<0,1>(t[12], t[12]);

  /* Combine results */
  t[0] = m[0];
  t[8] = m[4];
  t[1] = XOR(t[0], m[1]);
  t[2] = XOR(t[1], m[6]);
  t[1] = XOR(t[1], m[5]);
  t[2] = XOR(t[2], m[2]);
  t[7] = XOR(t[8], m[3]);
  t[6] = XOR(t[7], m[7]);
  t[7] = XOR(t[7], m[8]);
  t[6] = XOR(t[6], m[2]);
  t[5] = XOR(m[11], m[12]);

  t[3] = XOR(t[5], m[9]);
  t[3] = XOR(t[3], t[0]);
  t[3] = XOR(t[3], t[6]);

  t[4] = XOR(t[1], t[7]);
  t[4] = XOR(t[4], m[9]);
  t[4] = XOR(t[4], m[10]);
  t[4] = XOR(t[4], m[12]);

  t[5] = XOR(t[5], t[2]);
  t[5] = XOR(t[5], t[8]);
  t[5] = XOR(t[5], m[10]);

  t[9] = SHR128<8>(t[7]);
  t[7] = ALIGNR<8>(t[7], t[5]);
  t[5] = ALIGNR<8>(t[5], t[3]);
  t[3] = ALIGNR<8>(t[3], t[1]);
  t[1] = SHL128<8>(t[1]);

  z[0] = XOR(t[0], t[1]);
  z[1] = XOR(t[2], t[3]);
  z[2] = XOR(t[4], t[5]);
  z[3] = XOR(t[6], t[7]);
  z[4] = XOR(t[8], t[9]);
}

/* 7-term Karatsuba multiplication with 4-4-3 strategy. */
inline void poly_multiply_impl_64(std::integral_constant<size_t, 7>, limb_t z[7], const limb_t a[4], const limb_t b[4]) {
  limb_t t[4], e[4];

  /* Multiply lower part */
  poly_multiply_impl_64(std::integral_constant<size_t, 4>{}, z, a, b);

  /* Multiply upper part */
  poly_multiply_impl_64(std::integral_constant<size_t, 3>{}, z + 4, a + 2, b + 2);

  t[0] = XOR(a[0], a[2]);
  t[1] = XOR(a[1], a[3]);
  t[2] = XOR(b[0], b[2]);
  t[3] = XOR(b[1], b[3]);

  /* Multiply middle part */
  poly_multiply_impl_64(std::integral_constant<size_t, 4>{}, e, t + 2, t);

  /* Combine results */
  t[0] = XOR(e[0], z[4]);
  t[1] = XOR(e[1], z[5]);
  t[2] = XOR(e[2], z[6]);
  t[3] = XOR(e[3], z[3]);

  e[0] = XOR(t[0], z[0]);
  e[1] = XOR(t[1], z[1]);
  e[2] = XOR(t[2], z[2]);

  z[2] = XOR(z[2], e[0]);
  z[3] = XOR(z[3], e[1]);
  z[4] = XOR(z[4], e[2]);
  z[5] = XOR(z[5], t[3]);
}

/* 9-term Karatsuba multiplication with 5-5-4 strategy. */
inline void poly_multiply_impl_64(std::integral_constant<size_t, 9>, limb_t z[9], const limb_t a[5], const limb_t b[5]) {
  limb_t t[5], e[4], f[5], at[5], bt[5];

  /* Multiply lower part */
  poly_multiply_impl_64(std::integral_constant<size_t, 5>{}, z, a, b);

  /* Make local copy of a,b to not destroy them */
  at[4] = ALIGNR<8>(a[4], a[3]);
  at[3] = ALIGNR<8>(a[3], a[2]);
  at[2] = MOVE64(a[2]);
  at[1] = a[1];
  at[0] = a[0];

  bt[4] = ALIGNR<8>(b[4], b[3]);
  bt[3] = ALIGNR<8>(b[3], b[2]);
  bt[2] = MOVE64(b[2]);
  bt[1] = b[1];
  bt[0] = b[0];

  /* Prepare operands */
  t[0] = XOR(at[0], at[3]); // t0 = [ (a6+a1);(a5+a0) ]
  t[1] = XOR(at[1], at[4]); // t1 = [ (a8+a3);(a7+a2) ]
  t[2] = at[2]; // t2 = [ 0;a4 ]

  e[0] = XOR(bt[0], bt[3]); // e0 = [ (b6+b1);(b5+b0) ]
  e[1] = XOR(bt[1], bt[4]); // e1 = [ (b8+b3);(b7+b2) ]
  e[2] = bt[2]; // e2 = [ 0;b4 ]

  /* Multiply middle part */
  poly_multiply_impl_64(std::integral_constant<size_t, 5>{}, f, t, e);

  t[0] = XOR(f[0], z[0]);
  t[1] = XOR(f[1], z[1]);
  t[2] = XOR(f[2], z[2]);
  t[3] = XOR(f[3], z[3]);
  t[4] = XOR(f[4], z[4]);

  /* Multiply upper part */
  poly_multiply_impl_64(std::integral_constant<size_t, 4>{}, z + 5, at + 3, bt + 3);

  /* Combine results */
  e[0] = XOR(t[0], z[5]);
  e[1] = XOR(t[1], z[6]);
  e[2] = XOR(t[2], z[7]);
  e[3] = XOR(t[3], z[8]);

  f[0] = SHL128<8>(e[0]);
  z[2] = XOR(z[2], f[0]);
  f[1] = ALIGNR<8>(e[1], e[0]);
  z[3] = XOR(z[3], f[1]);
  f[2] = ALIGNR<8>(e[2], e[1]);
  z[4] = XOR(z[4], f[2]);
  f[3] = ALIGNR<8>(e[3], e[2]);
  z[5] = XOR(z[5], f[3]);
  f[4] = ALIGNR<8>(t[4], e[3]);
  z[6] = XOR(z[6], f[4]);
  f[0] = SHR128<8>(t[4]);
  z[7] = XOR(z[7], f[0]);
}

template <size_t NumWords>
inline void poly_square_impl_64(std::integral_constant<size_t, NumWords>, limb_t z[NumWords], const limb_t a[(NumWords+1)/2]) {
  limb_t x[2], sqrT, mask;

  sqrT = SET64(0x5554515045444140ul, 0x1514111005040100ul);
  mask = SET64(0x0F0F0F0F0F0F0F0Ful, 0x0F0F0F0F0F0F0F0Ful);

  constexpr static size_t num_limbs = (NumWords+1)/2;

  for (size_t limb_i = 0; limb_i < num_limbs; ++limb_i) {

    x[0] = AND(a[limb_i], mask);
    x[1] = SHR(a[limb_i], 4);
    x[1] = AND(x[1], mask);
    x[0] = SHUFFLE(sqrT, x[0]);
    x[1] = SHUFFLE(sqrT, x[1]);
    z[limb_i*2] = UNPACKLO8(x[0], x[1]);
    if (limb_i*2 + 1 < NumWords)
      z[limb_i*2 + 1] = UNPACKHI8(x[0], x[1]);
  }
}

#if 0 // generic implementation above should suffice
inline void poly_square_impl_64(std::integral_constant<size_t, 2>, limb_t z[2], const limb_t a[1]) {

  limb_t sqrT = SET64(0x5554515045444140ul, 0x1514111005040100ul);
  limb_t mask = SET64(0x0F0F0F0F0F0F0F0Ful, 0x0F0F0F0F0F0F0F0Ful);
  limb_t a1 = AND(a[0], mask);
  a1 = SHUFFLE(sqrT, a1);
  limb_t t0 = SHR(a[0], 4);
  t0 = AND(t0, mask);
  t0 = SHUFFLE(sqrT, t0);
  z[0] = UNPACKLO8(a1, t0);
  z[1] = UNPACKHI8(a1, t0);
}

inline void poly_square_impl_64(std::integral_constant<size_t, 3>, limb_t z[3], const limb_t a[2]) {
  limb_t x[2], sqrT, mask;

  sqrT = SET64(0x5554515045444140ul, 0x1514111005040100ul);
  mask = SET64(0x0F0F0F0F0F0F0F0Ful, 0x0F0F0F0F0F0F0F0Ful);

  x[0] = AND(a[0], mask);
  x[1] = SHR(a[0], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[0] = UNPACKLO8(x[0], x[1]);
  z[1] = UNPACKHI8(x[0], x[1]);

  x[0] = AND(a[1], mask);
  x[1] = SHR(a[1], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[2] = UNPACKLO8(x[0], x[1]);
}


inline void poly_square_impl_64(std::integral_constant<size_t, 4>, limb_t z[4], const limb_t a[2]) {
  limb_t x[2], sqrT, mask;

  sqrT = SET64(0x5554515045444140ul, 0x1514111005040100ul);
  mask = SET64(0x0F0F0F0F0F0F0F0Ful, 0x0F0F0F0F0F0F0F0Ful);

  x[0] = AND(a[0], mask);
  x[1] = SHR(a[0], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[0] = UNPACKLO8(x[0], x[1]);
  z[1] = UNPACKHI8(x[0], x[1]);

  x[0] = AND(a[1], mask);
  x[1] = SHR(a[1], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[2] = UNPACKLO8(x[0], x[1]);
  z[3] = UNPACKHI8(x[0], x[1]);
}

inline void poly_square_impl_64(std::integral_constant<size_t, 5>, limb_t z[5], const limb_t a[3]) {
  limb_t x[2], sqrT, mask;

  sqrT = SET64(0x5554515045444140ul, 0x1514111005040100ul);
  mask = SET64(0x0F0F0F0F0F0F0F0Ful, 0x0F0F0F0F0F0F0F0Ful);

  x[0] = AND(a[0], mask);
  x[1] = SHR(a[0], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[0] = UNPACKLO8(x[0], x[1]);
  z[1] = UNPACKHI8(x[0], x[1]);

  x[0] = AND(a[1], mask);
  x[1] = SHR(a[1], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[2] = UNPACKLO8(x[0], x[1]);
  z[3] = UNPACKHI8(x[0], x[1]);

  x[0] = AND(a[2], mask);
  x[1] = SHR(a[2], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[4] = UNPACKLO8(x[0], x[1]);
}

inline void poly_square_impl_64(std::integral_constant<size_t, 7>, limb_t z[7], const limb_t a[4]) {
  limb_t x[2], sqrT, mask;

  sqrT = SET64(0x5554515045444140ul, 0x1514111005040100ul);
  mask = SET64(0x0F0F0F0F0F0F0F0Ful, 0x0F0F0F0F0F0F0F0Ful);

  x[0] = AND(a[0], mask);
  x[1] = SHR(a[0], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[0] = UNPACKLO8(x[0], x[1]);
  z[1] = UNPACKHI8(x[0], x[1]);

  x[0] = AND(a[1], mask);
  x[1] = SHR(a[1], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[2] = UNPACKLO8(x[0], x[1]);
  z[3] = UNPACKHI8(x[0], x[1]);

  x[0] = AND(a[2], mask);
  x[1] = SHR(a[2], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[4] = UNPACKLO8(x[0], x[1]);
  z[5] = UNPACKHI8(x[0], x[1]);

  x[0] = AND(a[3], mask);
  x[1] = SHR(a[3], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[6] = UNPACKLO8(x[0], x[1]);
}

inline void poly_square_impl_64(std::integral_constant<size_t, 9>, limb_t z[9], const limb_t a[5]) {
  limb_t x[2], sqrT, mask;

  sqrT = SET64(0x5554515045444140ul, 0x1514111005040100ul);
  mask = SET64(0x0F0F0F0F0F0F0F0Ful, 0x0F0F0F0F0F0F0F0Ful);

  x[0] = AND(a[0], mask);
  x[1] = SHR(a[0], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[0] = UNPACKLO8(x[0], x[1]);
  z[1] = UNPACKHI8(x[0], x[1]);

  x[0] = AND(a[1], mask);
  x[1] = SHR(a[1], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[2] = UNPACKLO8(x[0], x[1]);
  z[3] = UNPACKHI8(x[0], x[1]);

  x[0] = AND(a[2], mask);
  x[1] = SHR(a[2], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[4] = UNPACKLO8(x[0], x[1]);
  z[5] = UNPACKHI8(x[0], x[1]);

  x[0] = AND(a[3], mask);
  x[1] = SHR(a[3], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[6] = UNPACKLO8(x[0], x[1]);
  z[7] = UNPACKHI8(x[0], x[1]);

  x[0] = AND(a[4], mask);
  x[1] = SHR(a[4], 4);
  x[1] = AND(x[1], mask);
  x[0] = SHUFFLE(sqrT, x[0]);
  x[1] = SHUFFLE(sqrT, x[1]);
  z[8] = UNPACKLO8(x[0], x[1]);
}

#endif // end non-generic implementation of squaring


}

template <size_t Bits>
inline BinaryPolynomial<Bits*2> operator*(BinaryPolynomial<Bits> const &a, BinaryPolynomial<Bits> const &b) {
  BinaryPolynomial<Bits*2> z;
  detail::poly_multiply_impl_64(std::integral_constant<size_t,div_ceil(Bits,64)>{},z.limbs, a.limbs, b.limbs);
  return z;
}

template <size_t Bits>
inline BinaryPolynomial<Bits*2> square(BinaryPolynomial<Bits> const &a) {
  BinaryPolynomial<Bits*2> z;
  detail::poly_square_impl_64(std::integral_constant<size_t,div_ceil(Bits,64)>{},z.limbs, a.limbs);
  return z;
}


}
}

#endif /* HEADER GUARD */
