#ifndef HEADER_GUARD_15779a5195888755419982aa8f3087eb
#define HEADER_GUARD_15779a5195888755419982aa8f3087eb

#include "./limb.hpp"
#include <x86intrin.h>

#if defined(__PCLMUL__)
#include <wmmintrin.h>
#endif

namespace jbms {
namespace binary_field {

namespace detail {

/* Load, store and extraction */
//#define	 	LOAD_64		_mm_loadl_epi64

inline limb_t LOAD128(limb_t const *x) { return *x; }
//#define	 	LOAD128		_mm_load_si128
//#define	 	STORE_64	_mm_storel_epi64

inline void STORE128(limb_t *x, limb_t v) { *x = v; }
//#define	 	STORE128	_mm_store_si128

// Note: this effectively works in reverse, i.e. big-endian argument format
inline limb_t SET64(uint64_t a, uint64_t b) {
  return limb_t{b,a};
}
//#define	 	SET64		_mm_set_epi64x
//#define	 	GET64		_mm_extract_epi64

/* Arithmetic */
//#define	 	CLMUL		_mm_clmulepi64_si128
inline limb_t SHUFFLE(limb_t a, limb_t mask) {
  return (limb_t)_mm_shuffle_epi8((__m128i)a, (__m128i)mask);
}
//#define	 	SHUFFLE		_mm_shuffle_epi8
inline limb_t XOR(limb_t a, limb_t b) {
  return a ^ b;
}
//#define	 	XOR			_mm_xor_si128
inline limb_t AND(limb_t a, limb_t b) {
  return a & b;
}
//#define	 	AND			_mm_and_si128
inline limb_t NAND(limb_t a, limb_t b) {
  return (~a) & b;
}

//#define	 	NAND		_mm_andnot_si128
inline limb_t OR(limb_t a, limb_t b) {
  return a | b;
}

//#define	 	OR			_mm_or_si128

inline limb_t SHL(limb_t a, unsigned int i) {
  return a << limb_t{i,i};
}
//#define	 	SHL			_mm_slli_epi64

inline limb_t SHR(limb_t a, unsigned int i) {
  return a >> limb_t{i,i};
}
//#define	 	SHR			_mm_srli_epi64
template <int i>
inline limb_t SHL128(limb_t a) {
  return (limb_t)_mm_slli_si128((__m128i)a, i);
}
//#define	 	SHL128		_mm_slli_si128
template <int i>
inline limb_t SHR128(limb_t a) {
  return (limb_t)_mm_srli_si128((__m128i)a, i);
}
//#define	 	SHR128		_mm_srli_si128

/* Memory alignment */
inline limb_t ZERO() {
  return limb_t{0,0};
}
//#define	 	ZERO		_mm_setzero_si128()
template <int i>
inline limb_t ALIGNR(limb_t a, limb_t b) {
  return (limb_t)_mm_alignr_epi8((__m128i)a, (__m128i)b, i);
}
//#define  	ALIGNR		_mm_alignr_epi8
inline limb_t MOVE64(limb_t a) {
  return (limb_t)_mm_move_epi64((__m128i)a);
}
//#define  	MOVE64		_mm_move_epi64
inline limb_t UNPACKLO8(limb_t a, limb_t b) {
  return (limb_t)_mm_unpacklo_epi8((__m128i)a, (__m128i)b);
}
//#define	 	UNPACKLO8	_mm_unpacklo_epi8
inline limb_t UNPACKHI8(limb_t a, limb_t b) {
  return (limb_t)_mm_unpackhi_epi8((__m128i)a, (__m128i)b);
}
//#define	 	UNPACKHI8	_mm_unpackhi_epi8
inline limb_t UNPACKLO64(limb_t a, limb_t b) {
  return (limb_t)_mm_unpacklo_epi64((__m128i)a, (__m128i)b);
}
//#define	 	UNPACKLO64	_mm_unpacklo_epi64
inline limb_t UNPACKHI64(limb_t a, limb_t b) {
  return (limb_t)_mm_unpackhi_epi64((__m128i)a,(__m128i)b);
}
//#define	 	UNPACKHI64	_mm_unpackhi_epi64


#ifdef __PCLMUL__
template <int a_part, int b_part>
inline limb_t poly_mul_vec(limb_t a, limb_t b) {
  return (limb_t)_mm_clmulepi64_si128((__m128i)a, (__m128i)b, a_part * 0x10 + b_part);
}
#else // C implementation

inline void poly_mul_impl(uint64_t *r1, uint64_t *r0, const uint64_t a, const uint64_t b)
	{
	uint64_t h, l, s;
	uint64_t tab[16], top3b = a >> 61;
	uint64_t a1, a2, a4, a8;

	a1 = a & (0x1FFFFFFFFFFFFFFFULL); a2 = a1 << 1; a4 = a2 << 1; a8 = a4 << 1;

	tab[ 0] = 0;     tab[ 1] = a1;       tab[ 2] = a2;       tab[ 3] = a1^a2;
	tab[ 4] = a4;    tab[ 5] = a1^a4;    tab[ 6] = a2^a4;    tab[ 7] = a1^a2^a4;
	tab[ 8] = a8;    tab[ 9] = a1^a8;    tab[10] = a2^a8;    tab[11] = a1^a2^a8;
	tab[12] = a4^a8; tab[13] = a1^a4^a8; tab[14] = a2^a4^a8; tab[15] = a1^a2^a4^a8;

	s = tab[b       & 0xF]; l  = s;
	s = tab[b >>  4 & 0xF]; l ^= s <<  4; h  = s >> 60;
	s = tab[b >>  8 & 0xF]; l ^= s <<  8; h ^= s >> 56;
	s = tab[b >> 12 & 0xF]; l ^= s << 12; h ^= s >> 52;
	s = tab[b >> 16 & 0xF]; l ^= s << 16; h ^= s >> 48;
	s = tab[b >> 20 & 0xF]; l ^= s << 20; h ^= s >> 44;
	s = tab[b >> 24 & 0xF]; l ^= s << 24; h ^= s >> 40;
	s = tab[b >> 28 & 0xF]; l ^= s << 28; h ^= s >> 36;
	s = tab[b >> 32 & 0xF]; l ^= s << 32; h ^= s >> 32;
	s = tab[b >> 36 & 0xF]; l ^= s << 36; h ^= s >> 28;
	s = tab[b >> 40 & 0xF]; l ^= s << 40; h ^= s >> 24;
	s = tab[b >> 44 & 0xF]; l ^= s << 44; h ^= s >> 20;
	s = tab[b >> 48 & 0xF]; l ^= s << 48; h ^= s >> 16;
	s = tab[b >> 52 & 0xF]; l ^= s << 52; h ^= s >> 12;
	s = tab[b >> 56 & 0xF]; l ^= s << 56; h ^= s >>  8;
	s = tab[b >> 60      ]; l ^= s << 60; h ^= s >>  4;

	/* compensate for the top three bits of a */

	if (top3b & 01) { l ^= b << 61; h ^= b >> 3; }
	if (top3b & 02) { l ^= b << 62; h ^= b >> 2; }
	if (top3b & 04) { l ^= b << 63; h ^= b >> 1; }

	*r1 = h; *r0 = l;
	}

template <int a_part, int b_part>
inline limb_t poly_mul_vec(limb_t a, limb_t b) {
  uint64_t r1, r0;
  poly_mul_impl(&r1, &r0, a[a_part], b[b_part]);
  return limb_t {r0, r1};
}

#endif

// #ifdef __RDRND__

// // Returns a 64-bit random value obtained via the RDRAND instruction.  Retries indefinitely.
// inline uint64_t rdrand64() {
//   unsigned long long result;
//   while (!_rdrand64_step(&result))
//     continue;
//   return result;
// }
// #endif // __RDRND__

}

inline bool is_zero_constant_time(limb_t a) {
  return _mm_testc_si128((__m128i)limb_t{0,0}, (__m128i)a);
}

inline limb_t select_constant_time(limb_t a, limb_t b, bool condition) {
  word_t word_mask = ~(word_t(condition) - 1);
  limb_t limb_mask{word_mask, word_mask};
  return (a & limb_mask) | (b & ~limb_mask);
}

}
}

#undef ALWAYS_INLINE


#endif /* HEADER GUARD */
