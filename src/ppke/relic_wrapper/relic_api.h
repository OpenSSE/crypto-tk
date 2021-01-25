#ifndef RELIC_API_H
#define RELIC_API_H
#include <sse/crypto/prf.hpp>

#include <cmath>
#include <cstdlib>
#include <cstring> // for memcpy

#include <algorithm> // for std::fill
#include <array>
#include <bitset>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <type_traits> // for static assert
#include <vector>

#include <sodium/utils.h>

// define classes
#ifdef __cplusplus
// gmp.h uses __cplusplus to decide if it's right to include c++ headers.
// At last on osx  causes error: conflicting types for 'operator<<'.
// undefinning __cplusplus "FIXES" this.
#include <gmpxx.h>
extern "C" {
#endif

#include <relic/relic.h>
#include <relic/relic_conf.h>

#ifdef __cplusplus
}
#endif

extern "C" {
#include "common.h"
}
// this exists to deal with a const issue with relic. we can either copy
// (guaranteed  to be safe) or just cast away the const under the assumption
// that the underlying methods are ocnst (which they are supposed to be already)
#ifdef RELICXX_UNCONST
#define RELICXX_G1unconst(x, y) G1& y = const_cast<G1&>(x)
#define RELICXX_G2unconst(x, y) G2& y = const_cast<G2&>(x)
#define RELICXX_GTunconst(x, y) GT& y = const_cast<GT&>(x)
#define RELICXX_ZRunconst(x, y) ZR& y = const_cast<ZR&>(x)
#else
#define RELICXX_G1unconst(x, y) G1 y(x)
#define RELICXX_G2unconst(x, y) G2 y(x)
#define RELICXX_GTunconst(x, y) GT y(x)

#define RELICXX_ZRunconst(x, y) ZR y(x)

#endif

// ensures that if we try to enable OpenMP support , it's enabled in relic or
// fails .
//  MULTI may not be defined , so we hav two asserts. One if it isn't, one it it
//  is.
#ifdef RELICXX_USE_OPENMP
#ifndef MULTI
static_assert(0,
              "Error. Relicxx is compiled to use OPENMP. But Relic is not "
              "configured to use any threading.");
#else
static_assert(MULTI == OPENMP,
              "Error. Relicxx compiled to use OPENMP. But Relic is not.");
#endif
#endif

#define convert_str(a) a /* nothing */

// Starting from commit 70884fc8b6d893bcc5fd41b8ca0c4d204e03f882, RELIC does not
// define RELIC_BN_BYTES anymore.
// Do it ourself if necessary.

#ifndef RELIC_BN_BYTES
#define RELIC_BN_BYTES RLC_CEIL(RLC_BN_BITS, 8)
#endif

namespace relicxx {
using bytes_vec = std::vector<uint8_t>;
[[noreturn]] void ro_error();

constexpr static uint8_t HASH_FUNCTION_STRINGS         = 0x00;
constexpr static uint8_t HASH_FUNCTION_BYTES_TO_Zr_CRH = 0x01;
constexpr static uint8_t HASH_FUNCTION_BYTES_TO_G1_ROM = 0x02;
constexpr static uint8_t HASH_FUNCTION_BYTES_TO_G2_ROM = 0x03;

class RelicDividByZero : public std::logic_error
{
public:
    explicit RelicDividByZero(std::string const& error)
        : std::logic_error(error)
    {
    }
};

void error_if_relic_not_init();
class ZR
{
public:
    bn_t z;
    bn_t order;
    bool isInit{false};
    ZR()
    {
        error_if_relic_not_init();
        bn_inits(z);
        bn_inits(order);
        g1_get_ord(order);
        isInit = true;
        bn_set_dig(z, 1);
    }

    explicit ZR(int /*x*/);
    explicit ZR(const std::string& str);
    ZR(const uint8_t* /*bytes*/, size_t /*len*/);
    explicit ZR(const bn_t y)
    {
        error_if_relic_not_init();
        bn_inits(z);
        bn_inits(order);
        g1_get_ord(order);
        isInit = true;
        bn_copy(z, y);
    }
    ZR(const ZR& w)
    {
        error_if_relic_not_init();
        bn_inits(z);
        bn_inits(order);
        bn_copy(z, w.z);
        bn_copy(order, w.order);
        isInit = true;
    }

#ifdef RELICXX_MOVEZR
    ZR(ZR&& other)
    {
        *this = std::move(other);
    }

    ZR& operator=(ZR&& rhs)
    {
        if (this != &rhs && rhs.isInit) {
            isInit     = rhs.isInit;
            rhs.isInit = false;
            if (isInit) {
                bn_free(z);
                bn_free(order);
            }
#if ALLOC == AUTO
            z[0]     = rhs.z[0];
            order[0] = rhs.order[0];
            sodium_memzero((&rhs.z[0]), sizeof(rhs.z[0]));
#else
            z         = rhs.z;
            order     = rhs.order;
            rhs.z     = nullptr;
            rhs.order = nulltpr;
#endif
        }
        return *this;
    }
#endif
    ~ZR()
    {
        if (isInit) {
            bn_free(z);
            bn_free(order);
        }
    }
    ZR& operator=(const ZR& w)
    {
        if (isInit) {
            bn_copy(z, w.z);
            bn_copy(order, w.order);
        } else {
            {
                {
                    {
                        {
                            ro_error();
                        }
                    }
                }
            }
        }
        return *this;
    }

    size_t               byte_size() const;
    bool                 ismember() const;
    ZR                   inverse() const;
    std::vector<uint8_t> getBytes() const;
    void                 writeBytes(uint8_t* bytes) const;

    friend ZR hashToZR(const bytes_vec& /*b*/);
    friend ZR power(const ZR& /*x*/, int /*r*/);
    friend ZR power(const ZR& /*x*/, const ZR& /*r*/);
    friend ZR operator-(const ZR& /*x*/);
    friend ZR operator-(const ZR& /*x*/, const ZR& /*y*/);
    friend ZR operator+(const ZR& /*x*/, const ZR& /*y*/);
    friend ZR operator*(const ZR& /*x*/, const ZR& /*y*/);
    friend ZR operator/(const ZR& /*x*/, const ZR& /*y*/);
    friend ZR operator&(const ZR& /*a*/, const ZR& /*b*/); // bitwise-AND
    //    friend ZR operator|(const ZR&, const ZR&);  // bitwise-OR
    //    friend ZR operator^(const ZR&, const ZR&);  // bitwise-XOR
    friend ZR operator<<(const ZR& /*a*/, int /*b*/);
    friend ZR operator>>(const ZR& /*a*/, int /*b*/);

    friend std::ostream& operator<<(std::ostream& /*s*/, const ZR& /*zr*/);
    friend bool          operator==(const ZR& x, const ZR& y)
    {
        if (bn_cmp(x.z, y.z) == RLC_EQ) {
            {
                {
                    {
                        {
                            return true;
                        }
                    }
                }
            }
        }
        {
            {
                {
                    {
                        {
                            return false;
                        }
                    }
                }
            }
        }
    }
    friend bool operator!=(const ZR& x, const ZR& y)
    {
        if (bn_cmp(x.z, y.z) != RLC_EQ) {
            {
                {
                    {
                        {
                            return true;
                        }
                    }
                }
            }
        }
        {
            {
                {
                    {
                        {
                            return false;
                        }
                    }
                }
            }
        }
    }
    friend bool operator>(const ZR& x, const ZR& y)
    {
        if (bn_cmp(x.z, y.z) == RLC_GT) {
            {
                {
                    {
                        {
                            return true;
                        }
                    }
                }
            }
        }
        {
            {
                {
                    {
                        {
                            return false;
                        }
                    }
                }
            }
        }
    }
    friend bool operator<(const ZR& x, const ZR& y)
    {
        if (bn_cmp(x.z, y.z) == RLC_LT) {
            {
                {
                    {
                        {
                            return true;
                        }
                    }
                }
            }
        }
        {
            {
                {
                    {
                        {
                            return false;
                        }
                    }
                }
            }
        }
    }
};


ZR hashToZR(const bytes_vec& b);

class G1
{
public:
    constexpr static uint16_t kByteSize        = 1 + 2 * RLC_FP_BYTES;
    constexpr static uint16_t kCompactByteSize = 1 + RLC_FP_BYTES;


    g1_t g;
    bool isInit{false};
    G1()
    {
        error_if_relic_not_init();
        g1_inits(g);
        isInit = true;
        g1_set_infty(g);
    }
    G1(const G1& w)
    {
        g1_inits(g);
        g1_copy(g, w.g);
        isInit = true;
    }
    G1(const uint8_t* bytes, bool compress);

    ~G1()
    {
        if (isInit) {
            {
                g1_free(g)
            }
        }
    }
#ifdef RELICXX_MOVEG1
    G1(G1&& other)
    {
        *this = std::move(other);
    }
    G1& operator=(G1&& rhs)
    {
        if (this != &rhs && rhs.isInit) {
            isInit     = rhs.isInit;
            rhs.isInit = false;
            if (isInit) {
                g1_free(g);
            }
#if ALLOC == AUTO
            g[0] = rhs.g[0];
            sodium_memzero((&rhs.g[0]), sizeof(rhs.g[0]));
#else
            g         = rhs.g;
            rhs.g     = nullptr;
#endif
        }
        return *this;
    }

#endif
    G1& operator=(const G1& w)
    {
        if (isInit) {
            {
                {
                    {
                        {
                            g1_copy(g, w.g);
                        }
                    }
                }
            }
        } else {
            {
                {
                    {
                        {
                            ro_error();
                        }
                    }
                }
            }
        }
        return *this;
    }

    bool                 ismember(const bn_t /*order*/) const;
    std::vector<uint8_t> getBytes(bool compress = false) const;
    void writeBytes(uint8_t* bytes, bool compress = false) const;


    friend G1            hashToG1(const bytes_vec& /*b*/);
    friend G1            power(const G1& /*g*/, const ZR& /*zr*/);
    friend G1            operator-(const G1& /*x*/);
    friend G1            operator-(const G1& /*x*/, const G1& /*y*/);
    friend G1            operator+(const G1& /*x*/, const G1& /*y*/);
    friend std::ostream& operator<<(std::ostream& /*s*/, const G1& /*g1*/);
    friend bool          operator==(const G1& x, const G1& y)
    {
        return g1_cmp(x.g, y.g) == RLC_EQ;
    }
    friend bool operator!=(const G1& x, const G1& y)
    {
        return g1_cmp(x.g, y.g) != RLC_EQ;
    }
};

class G2
{
public:
    constexpr static uint16_t kByteSize        = 1 + 4 * RLC_FP_BYTES;
    constexpr static uint16_t kCompactByteSize = 1 + 2 * RLC_FP_BYTES;

    g2_t g;
    bool isInit{false};
    G2()
    {
        error_if_relic_not_init();
        g2_inits(g);
        isInit = true;
        g2_set_infty(g);
    }
    G2(const G2& w)
    {
        g2_inits(g);
        g2_copy(g, const_cast<G2&>(w).g);
        isInit = true;
    }
    G2(const uint8_t* bytes, bool compress);

    ~G2()
    {
        if (isInit) {
            {
                g2_free(g)
            }
        }
    }
#ifdef RELICXX_MOVEG2
    G2(G2&& other)
    {
        *this = std::move(other);
    }
    G2& operator=(G2&& rhs)
    {
        if (this != &rhs && rhs.isInit) {
            isInit     = rhs.isInit;
            rhs.isInit = false;
            if (isInit) {
                g2_free(g);
            }
#if ALLOC == AUTO
            g[0] = rhs.g[0];
            sodium_memzero((&rhs.g[0]), sizeof(rhs.g[0]));
#else
            g         = rhs.g;
            rhs.g     = nulltpr;
#endif
        }
        return *this;
    }
#endif

    G2& operator=(const G2& w)
    {
        if (isInit) {
            {
                {
                    {
                        {
                            g2_copy(g, const_cast<G2&>(w).g);
                        }
                    }
                }
            }
        } else {
            {
                {
                    {
                        {
                            ro_error();
                        }
                    }
                }
            }
        }
        return *this;
    }
    bool                 ismember(bn_t /*order*/);
    std::vector<uint8_t> getBytes(bool compress = false) const;
    void writeBytes(uint8_t* bytes, bool compress = false) const;

    friend G2            hashToG2(const bytes_vec& /*b*/);
    friend G2            power(const G2& /*g*/, const ZR& /*zr*/);
    friend G2            operator-(const G2& /*x*/);
    friend G2            operator-(const G2& /*x*/, const G2& /*y*/);
    friend G2            operator+(const G2& /*x*/, const G2& /*y*/);
    friend std::ostream& operator<<(std::ostream& s, const G2& /*g2*/);
    friend bool          operator==(const G2& x, const G2& y)
    {
        return g2_cmp(const_cast<G2&>(x).g, const_cast<G2&>(y).g) == RLC_EQ;
    }
    friend bool operator!=(const G2& x, const G2& y)
    {
        return g2_cmp(const_cast<G2&>(x).g, const_cast<G2&>(y).g) != RLC_EQ;
    }
};

class GT
{
public:
    constexpr static uint16_t kByteSize        = 12 * RLC_FP_BYTES;
    constexpr static uint16_t kCompactByteSize = 8 * RLC_FP_BYTES;

    gt_t g;
    bool isInit{false};
    GT()
    {
        error_if_relic_not_init();
        gt_inits(g);
        isInit = true;
        gt_set_unity(g);
    }
    GT(const GT& x)
    {
        error_if_relic_not_init();
        gt_inits(g);
        isInit = true;
        gt_copy(g, const_cast<GT&>(x).g);
    }
    GT(const uint8_t* bytes, bool compress);

    ~GT()
    {
        if (isInit) {
            {
                gt_free(g)
            }
        }
    }

    GT& operator=(const GT& x)
    {
        if (isInit) {
            {
                {
                    {
                        {
                            gt_copy(g, const_cast<GT&>(x).g);
                        }
                    }
                }
            }
        } else {
            {
                {
                    {
                        {
                            ro_error();
                        }
                    }
                }
            }
        }
        return *this;
    }
#ifdef RELICXX_MOVEGT
    GT& operator=(GT&& rhs)
    {
        if (this != &rhs && rhs.isInit) {
            isInit     = rhs.isInit;
            rhs.isInit = false;
            if (isInit) {
                gt_free(g);
            }
#if ALLOC == AUTO
            std::memcpy(*g, *(rhs.g), sizeof(g));
            sodium_memzero((&rhs.g[0]), sizeof(rhs.g[0]));
#else
            g         = rhs.g;
            rhs.g     = nullptr;
#endif
        }
        return *this;
    }
#endif

    bool                 ismember(bn_t /*order*/);
    std::vector<uint8_t> getBytes(bool compress = false) const;
    void getBytes(bool compress, const size_t out_len, uint8_t* out) const;
    void writeBytes(uint8_t* bytes, bool compress) const;

    friend GT            pairing(const G1&, const G1&);
    friend GT            pairing(const G1& /*g1*/, const G2& /*g2*/);
    friend GT            power(const GT& /*g*/, const ZR& /*zr*/);
    friend GT            operator-(const GT& /*g*/);
    friend GT            operator/(const GT& /*x*/, const GT& /*y*/);
    friend GT            operator*(const GT& /*x*/, const GT& /*y*/);
    friend std::ostream& operator<<(std::ostream& s, const GT& /*gt*/);
    friend bool          operator==(const GT& x, const GT& y)
    {
        return gt_cmp(const_cast<GT&>(x).g, const_cast<GT&>(y).g) == RLC_EQ;
    }
    friend bool operator!=(const GT& x, const GT& y)
    {
        return gt_cmp(const_cast<GT&>(x).g, const_cast<GT&>(y).g) != RLC_EQ;
    }
};

class relicResourceHandle
{
public:
    /**
     * Tries to initialize relic.  If allowAlreadyInitilazed, will
     * simply become a no op if someone has already initialized the
     * code.
     * @param allowAlreadyInitialized  If true, the constructor does not throw
     *                                 if RELIC is already initialized
     *
     * @exception std::runtime_error   RELIC was already initialized or failed
     *                                 to initialize
     */
    explicit relicResourceHandle(const bool allowAlreadyInitialized = true);
    ~relicResourceHandle();

    // you cannot meaningfully copy this resource
    relicResourceHandle(const relicResourceHandle& t) = delete;
    bool isInitalized() const;

private:
    bool isInit{false};
};


class PairingGroup
{
public:
    PairingGroup();
    ~PairingGroup();

    constexpr static unsigned int kStatisticalSecurity = 32;
    constexpr static unsigned int kPrfOutputSize
        = RELIC_BN_BYTES + kStatisticalSecurity / 8;

    ZR randomZR() const;
    ZR pseudoRandomZR(const sse::crypto::Prf<kPrfOutputSize>& prf,
                      const std::string&                      seed) const;


    G1 randomG1() const;
    G2 randomG2() const;
    GT randomGT() const;

    G1 generatorG1() const;
    G2 generatorG2() const;
    GT generatorGT() const;


    bool ismember(ZR& /*zr*/);
    bool ismember(G1& /*g*/);
    bool ismember(GT& /*g*/);
    bool ismember(G2& /*g*/);


    G2 random(G2_type) const;
    G2 mul(const G2& /*g*/, const G2& /*h*/) const;
    G2 div(const G2& /*g*/, const G2& /*h*/) const;
    G2 exp(const G2& /*g*/, const ZR& /*r*/) const;
    G2 exp(const G2& /*g*/, const int& /*r*/) const;
    GT pair(const G1& /*g*/, const G2& /*h*/) const;
    GT pair(const G2& /*h*/, const G1& /*g*/) const;
    ZR order() const; // returns the order of the group

    ZR hashListToZR(const std::string& str) const;
    ZR hashListToZR(const bytes_vec& /*b*/) const;

    template<size_t N>
    ZR hashListToZR(const std::array<uint8_t, N>& arr) const
    {
        bytes_vec b(arr.begin(), arr.end());
        return hashToZR(b);
    }

    G1 hashListToG1(const std::string& str) const;
    G1 hashListToG1(const bytes_vec& /*b*/) const;
    G2 hashListToG2(const bytes_vec& /*b*/) const;

    GT  pair(const G1&, const G1&) const;
    int mul(const int& /*g*/, const int& /*h*/) const;
    ZR  mul(const ZR& /*g*/, const ZR& /*h*/) const;
    G1  mul(const G1& /*g*/, const G1& /*h*/) const;
    GT  mul(const GT& /*g*/, const GT& /*h*/) const;
    int div(const int& /*g*/, const int& /*h*/) const;
    ZR  div(const int& /*g*/, const ZR& /*h*/) const;
    ZR  div(const ZR& /*g*/, const ZR& /*h*/) const;
    G1  div(const G1& /*g*/, const G1& /*h*/) const;
    GT  div(const GT& /*g*/, const GT& /*h*/) const;

    ZR exp(const ZR& /*x*/, const int& /*y*/) const;
    ZR exp(const ZR& /*x*/, const ZR& /*y*/) const;
    G1 exp(const G1& /*g*/, const ZR& /*r*/) const;
    G1 exp(const G1& /*g*/, const int& /*r*/) const;
    GT exp(const GT& /*g*/, const ZR& /*r*/) const;
    GT exp(const GT& /*g*/, const int& /*r*/) const;

    ZR  add(const ZR& /*g*/, const ZR& /*h*/) const;
    int add(const int& /*g*/, const int& /*h*/) const;

    int         sub(const int& /*g*/, const int& /*h*/) const;
    ZR          sub(const ZR& /*g*/, const ZR& /*h*/) const;
    ZR          neg(const ZR& /*r*/) const;
    ZR          inv(const ZR& /*r*/) const;
    G1          inv(const G1& /*g*/) const;
    G2          inv(const G2& /*g*/) const;
    GT          inv(const GT& /*g*/) const;
    std::string aes_key(const GT& g);

private:
    bool isInit{false};
    bn_t grp_order;
};

} // namespace relicxx
#endif
