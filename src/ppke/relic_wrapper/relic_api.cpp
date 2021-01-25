#include "relic_api.h"

#include <cassert>

#include <stdexcept>

#include <sodium/utils.h>

namespace relicxx {

[[noreturn]] void ro_error()
{
    throw std::invalid_argument("writing to read only object");
}

void error_if_relic_not_init()
{
    if (nullptr == core_get()) {
        throw std::runtime_error(
            "\n\nERROR. relic core_get() returned null. Relic is probably not "
            "initialized.\n ??? DID YOU INITIALIZE LIBFORWARDSEC ???\n"
            "You need to initialize the library once per thread by grabbing an "
            "instance of relicxx::relicResourceHandle\n"
            "and holding it until you are done with the library/thread.\n");
    }
}

static void invertZR(ZR& c, const ZR& a, const bn_t order)
{
    ZR   a1 = a;
    bn_t s;
    bn_inits(s);
    // compute c = (1 / a) mod n
    bn_gcd_ext(s, c.z, nullptr, a1.z, order);
    if (bn_sign(c.z) == RLC_NEG) {
        bn_add(c.z, c.z, order);
    }
    bn_free(s);
}

// Begin ZR-specific classes
ZR::ZR(int x)
{
    error_if_relic_not_init();
    bn_inits(z);
    bn_inits(order);
    g1_get_ord(order);
    isInit = true;
    if (x < 0) {
        bn_set_dig(z, static_cast<dig_t>(-x)); // set positive value
        bn_neg(z, z);                          // set bn to negative
    } else {
        bn_set_dig(z, static_cast<dig_t>(x));
    }
}

ZR::ZR(const std::string& str)
{
    error_if_relic_not_init();
    bn_inits(z);
    bn_inits(order);
    g1_get_ord(order);
    isInit = true;
    bn_read_str(z, str.c_str(), static_cast<int>(str.size()), DECIMAL);
    // bn_mod(z, z, order);
}

ZR::ZR(const uint8_t* bytes, size_t len)
{
    error_if_relic_not_init();
    bn_inits(z);
    bn_inits(order);
    g1_get_ord(order);
    isInit = true;

    bn_read_bin(z, bytes, static_cast<int>(len));
}

void ZR::writeBytes(uint8_t* bytes) const
{
    bn_write_bin(bytes, RELIC_BN_BYTES, z);
}


ZR ZR::inverse() const
{
    ZR i;
    invertZR(i, ZR(z), i.order);
    return i;
}

ZR operator+(const ZR& x, const ZR& y)
{
    ZR zr;
    bn_add(zr.z, x.z, y.z);
    bn_mod(zr.z, zr.z, zr.order);
    return zr;
}

ZR operator-(const ZR& x, const ZR& y)
{
    ZR zr;

    bn_sub(zr.z, x.z, y.z);
    if (bn_sign(zr.z) == RLC_NEG) {
        bn_add(zr.z, zr.z, zr.order);
    } else {
        bn_mod(zr.z, zr.z, zr.order);
    }
    return zr;
}

ZR operator-(const ZR& x)
{
    ZR zr;
    bn_neg(zr.z, x.z);
    if (bn_sign(zr.z) == RLC_NEG) {
        bn_add(zr.z, zr.z, zr.order);
    }
    return zr;
}


ZR operator*(const ZR& x, const ZR& y)
{
    ZR zr;
    bn_mul(zr.z, x.z, y.z);
    if (bn_sign(zr.z) == RLC_NEG) {
        bn_add(zr.z, zr.z, zr.order);
    } else {
        bn_mod(zr.z, zr.z, zr.order);
    }

    return zr;
}

ZR operator/(const ZR& x, const ZR& y)
{
    if (bn_is_zero(y.z) != 0) {
        throw RelicDividByZero("divide by zero");
    }
    ZR i;
    invertZR(i, y, i.order);
    return x * i;
}

ZR power(const ZR& x, int r)
{
    ZR zr;
    bn_mxp(zr.z, x.z, ZR(r).z, zr.order);
    return zr;
}


ZR power(const ZR& x, const ZR& r)
{
    ZR zr;
    bn_mxp(zr.z, x.z, r.z, zr.order);
    return zr;
}

ZR hashToZR(const bytes_vec& b)
{
    static_assert(sizeof(HASH_FUNCTION_BYTES_TO_G1_ROM) == 1,
                  "Invalid type for HASH_FUNCTION_BYTES_TO_Zr_CRH. Its size "
                  "should be 1 byte");

    bytes_vec data(sizeof(HASH_FUNCTION_BYTES_TO_Zr_CRH) + b.size());
    data[0] = HASH_FUNCTION_BYTES_TO_Zr_CRH;
    std::copy(b.begin(), b.end(), data.begin() + 1);

    ZR                                        zr;
    constexpr unsigned int                    digest_len = SHA_LEN;
    std::array<unsigned char, digest_len + 1> digest;
    memset(digest.data(), 0, digest_len);
    SHA_FUNC(digest.data(), data.data(), static_cast<int>(data.size()));
    bn_read_bin(zr.z, digest.data(), digest_len);
    if (bn_cmp(zr.z, zr.order) == RLC_GT) {
        bn_mod(zr.z, zr.z, zr.order);
    }
    return zr;
}

size_t ZR::byte_size() const
{
    return static_cast<size_t>(bn_size_bin(z));
}

bool ZR::ismember() const
{
    return ((bn_cmp(z, order) < RLC_EQ) && (bn_sign(z) == RLC_POS));
}

std::vector<uint8_t> ZR::getBytes() const
{
    std::vector<uint8_t> data(RELIC_BN_BYTES);
    bn_write_bin(&data[0], RELIC_BN_BYTES, z);
    return data;
}

std::ostream& operator<<(std::ostream& s, const ZR& zr)
{
    size_t            length = static_cast<size_t>(bn_size_str(zr.z, DECIMAL));
    std::vector<char> data(length + 1);
    memset(data.data(), 0, length);
    bn_write_str(data.data(), static_cast<int>(length), zr.z, DECIMAL);
    std::string s1(data.data(), length);
    s << s1;
    sodium_memzero(data.data(), length);
    return s;
}

ZR operator<<(const ZR& a, int b)
{
    // left shift
    ZR zr;
    bn_lsh(zr.z, a.z, b);
    if (bn_cmp(zr.z, zr.order) == RLC_GT) {
        bn_mod(zr.z, zr.z, zr.order);
    }
    return zr;
}

ZR operator>>(const ZR& a, int b)
{
    // right shift
    ZR zr;
    bn_rsh(zr.z, a.z, b);
    return zr;
}

ZR operator&(const ZR& a, const ZR& b)
{
    int  i;
    int  d = (a.z->used > b.z->used) ? b.z->used : a.z->used;
    bn_t c;
    bn_inits(c);

    for (i = 0; i < d; i++) {
        c->dp[i] = (a.z->dp[i] & b.z->dp[i]);
    }

    c->used = d;
    ZR zr(c);
    bn_free(c);
    return zr;
}

// ZR operator|(const ZR& a, const ZR& b)
//{
//	int i, d = (a.z->used > b.z->used) ? b.z->used : a.z->used;
//	bn_t c;
//	bn_inits(c);
//
//	for(i = 0; i < d; i++)
//		c->dp[i] = a.z->dp[i] | b.z->dp[i];
//
//	c->used = d;
//	ZR zr(c);
//	bn_free(c);
//	return zr;
//}

// ZR operator^(const ZR& a, const ZR& b)
//{
//	int i, d = (a.z->used > b.z->used) ? a.z->used : b.z->used;
//	bn_t c;
//	bn_inits(c);
//
//	for(i = 0; i < d; i++)
//		c->dp[i] = a.z->dp[i] ^ b.z->dp[i];
//
//	c->used = d;
//	ZR zr(c);
//	bn_free(c);
//	return zr;
//}


// End ZR-specific classes

// Begin G1-specific classes
G1::G1(const uint8_t* bytes, bool compress)
{
    error_if_relic_not_init();
    g1_inits(g);
    isInit = true;
    g1_read_bin(g, bytes, (compress) ? kCompactByteSize : kByteSize);
}


G1 operator+(const G1& x, const G1& y)
{
    G1 z;
    g1_add(z.g, x.g, y.g);
    g1_norm(z.g, z.g);

    return z;
}

G1 operator-(const G1& x, const G1& y)
{
    G1 z;
    g1_sub(z.g, x.g, y.g);
    g1_norm(z.g, z.g);

    return z;
}

G1 operator-(const G1& x)
{
    G1 z;
    g1_neg(z.g, x.g);
    return z;
}

G1 power(const G1& g, const ZR& zr)
{
    G1 g1;
    g1_mul(g1.g, const_cast<ep_st*>(g.g), const_cast<bn_st*>(zr.z));
    return g1;
}

G1 hashToG1(const bytes_vec& b)
{
    G1 g1;

    static_assert(sizeof(HASH_FUNCTION_BYTES_TO_G1_ROM) == 1,
                  "Invalid type for HASH_FUNCTION_BYTES_TO_G1_ROM. Its size "
                  "should be 1 byte");
    bytes_vec data(sizeof(HASH_FUNCTION_BYTES_TO_G1_ROM) + b.size());
    data[0] = HASH_FUNCTION_BYTES_TO_G1_ROM;
    std::copy(b.begin(), b.end(), data.begin() + 1);

    // map internally already hashes.
    g1_map(g1.g, data.data(), static_cast<int>(data.size()));
    return g1;
}

bool G1::ismember(const bn_t order) const
{
    bool result = false;
    g1_t r;
    g1_inits(r);

    g1_mul(r, const_cast<ep_st*>(g), const_cast<bn_st*>(order));
    if (g1_is_infty(r) == 1) {
        result = true;
    }
    {
        g1_free(r)
    }
    return result;
}

std::vector<uint8_t> G1::getBytes(bool compress) const
{
    size_t               l = static_cast<size_t>(g1_size_bin(g, compress));
    std::vector<uint8_t> data(l);
    g1_write_bin(&data[0], static_cast<int>(data.size()), g, compress);
    return data;
}

void G1::writeBytes(uint8_t* bytes, bool compress) const
{
    int l = g1_size_bin(g, compress);

    assert(l == ((compress) ? kCompactByteSize : kByteSize));

    g1_write_bin(bytes, l, g, compress);
}

std::ostream& operator<<(std::ostream& s, const G1& g1)
{
    // Save the format of the stream
    std::ios_base::fmtflags saved_flags(s.flags());

    auto data = g1.getBytes();
    s << "0x";
    for (auto i : data) {
        s << std::hex << static_cast<unsigned int>(data[i]);
    }
    s << std::endl;

    // Reset the flags
    s.flags(saved_flags);

    return s;
}

// End G1-specific classes

// Begin G2-specific classes
G2::G2(const uint8_t* bytes, bool compress)
{
    error_if_relic_not_init();
    g2_inits(g);
    isInit = true;
    g2_read_bin(g,
                const_cast<uint8_t*>(bytes),
                (compress) ? kCompactByteSize : kByteSize);
}

G2 operator+(const G2& x, const G2& y)
{
    G2 z;
    RELICXX_G2unconst(x, x1);
    RELICXX_G2unconst(y, y1);
    {g2_add(z.g, x1.g, y1.g)} g2_norm(z.g, z.g);
    return z;
}

G2 operator-(const G2& x, const G2& y)
{
    G2 z;
    RELICXX_G2unconst(x, x1);
    RELICXX_G2unconst(y, y1);
    g2_sub(z.g, x1.g, y1.g);
    g2_norm(z.g, z.g);
    return z;
}

G2 operator-(const G2& x)
{
    G2 z;
    RELICXX_G2unconst(x, x1);
    g2_neg(z.g, x1.g);
    return z;
}

G2 power(const G2& g, const ZR& zr)
{
    G2 g2;
    RELICXX_G2unconst(g, g1);
    RELICXX_ZRunconst(zr, zr1);
    g2_mul(g2.g, g1.g, zr1.z);
    return g2;
}

G2 hashToG2(const bytes_vec& b)
{
    static_assert(sizeof(HASH_FUNCTION_BYTES_TO_G2_ROM) == 1,
                  "Invalid type for HASH_FUNCTION_BYTES_TO_G1_ROM. Its size "
                  "should be 1 byte");

    G2 g2;

    bytes_vec data(sizeof(HASH_FUNCTION_BYTES_TO_G1_ROM) + b.size());
    data[0] = HASH_FUNCTION_BYTES_TO_G1_ROM;
    std::copy(b.begin(), b.end(), data.begin() + 1);

    // map internally already hashes.
    g2_map(g2.g, data.data(), static_cast<int>(data.size()));
    return g2;
}

bool G2::ismember(bn_t order)
{
    bool result = false;
    g2_t r;
    g2_inits(r);
    g2_mul(r, g, order);
    if (g2_is_infty(r) == 1) {
        result = true;
    }
    {
        g2_free(r)
    }
    return result;
}

std::vector<uint8_t> G2::getBytes(bool compress) const
{
    RELICXX_G2unconst(*this, gg);
    int l = g2_size_bin(gg.g, compress);

    std::vector<uint8_t> data(static_cast<size_t>(l));
    g2_write_bin(&data[0], l, gg.g, compress);
    return data;
}

void G2::writeBytes(uint8_t* bytes, bool compress) const
{
    int l = g2_size_bin(const_cast<G2*>(this)->g, compress);

    assert(l == ((compress) ? kCompactByteSize : kByteSize));

    g2_write_bin(bytes, l, const_cast<G2*>(this)->g, compress);
}


std::ostream& operator<<(std::ostream& s, const G2& g2)
{
    // Save the format of the stream
    std::ios_base::fmtflags saved_flags(s.flags());

    auto data = g2.getBytes();
    s << "0x";
    for (auto i : data) {
        s << std::hex << static_cast<unsigned int>(data[i]);
    }
    s << std::endl;

    // Reset the flags
    s.flags(saved_flags);

    return s;
}

// End G2-specific classes

// Begin GT-specific classes
GT::GT(const uint8_t* bytes, bool compress)
{
    error_if_relic_not_init();
    gt_inits(g);
    isInit = true;
    gt_read_bin(g,
                const_cast<uint8_t*>(bytes),
                (compress) ? kCompactByteSize : kByteSize);
}

GT operator*(const GT& x, const GT& y)
{
    GT z;
    GT x1 = x;
    GT y1 = y;
    gt_mul(z.g, x1.g, y1.g);
    return z;
}

GT operator/(const GT& x, const GT& y)
{
    GT z;
    RELICXX_GTunconst(x, x1);
    RELICXX_GTunconst(y, y1);
    // z = x * y^-1
    gt_t t;
    gt_inits(t);
    gt_inv(t, y1.g);
    gt_mul(z.g, x1.g, t);
    {
        gt_free(t)
    }
    return z;
}

GT power(const GT& g, const ZR& zr)
{
    GT gt;
    RELICXX_GTunconst(g, gg);
    RELICXX_ZRunconst(zr, zr1);
    if (zr == ZR(-1)) { // find efficient way for comparing bn_t to ints
        // compute inverse
        return -g;
    }

    {
        gt_exp(gt.g, gg.g, zr1.z)
    }
    return gt;
}

GT operator-(const GT& g)
{
    GT gt;
    RELICXX_GTunconst(g, gg);
    gt_inv(gt.g, gg.g);
    return gt;
}

GT pairing(const G1& g1, const G2& g2)
{
    GT gt;
    RELICXX_G1unconst(g1, g11);
    RELICXX_G2unconst(g2, g22);
    /* compute optimal ate pairing */
    pp_map_oatep_k12(gt.g, g11.g, g22.g);
    // pp_map_k12(gt.g, g11.g, g22.g);
    return gt;
}


bool GT::ismember(bn_t order)
{
    bool result = false;
    gt_t r;
    gt_inits(r);
    {
        gt_exp(r, g, order)
    }
    if (gt_is_unity(r) == 1) {
        result = true;
    }
    {
        gt_free(r)
    }
    return result;
}

std::vector<uint8_t> GT::getBytes(bool compress) const
{
    RELICXX_GTunconst(*this, gg);
    int l = gt_size_bin(gg.g, compress);

    std::vector<uint8_t> data(static_cast<size_t>(l));
    gt_write_bin(&data[0], l, gg.g, compress);
    return data;
}

void GT::getBytes(bool compress, const size_t out_len, uint8_t* out) const
{
    RELICXX_GTunconst(*this, gg);
    size_t l = static_cast<size_t>(gt_size_bin(gg.g, compress));

    if (l < out_len) {
        // fill the rest with 0's
        for (size_t i = l; i < out_len; i++) {
            out[i] = 0x00;
        }
    }
    gt_write_bin(out, static_cast<int>(RLC_MIN(l, out_len)), gg.g, compress);
}


void GT::writeBytes(uint8_t* bytes, bool compress) const
{
    int l = gt_size_bin(const_cast<GT*>(this)->g, compress);

    assert(l == ((compress) ? kCompactByteSize : kByteSize));

    gt_write_bin(bytes, l, const_cast<GT*>(this)->g, compress);
}

std::ostream& operator<<(std::ostream& s, const GT& gt)
{
    // Save the format of the stream
    std::ios_base::fmtflags saved_flags(s.flags());

    auto data = gt.getBytes();
    s << "0x";
    for (auto i : data) {
        s << std::hex << static_cast<unsigned int>(data[i]);
    }
    s << std::endl;

    // Reset the flags
    s.flags(saved_flags);

    return s;
}

relicResourceHandle::relicResourceHandle(const bool allowAlreadyInitialized)
{
    isInit = false;
    if (nullptr != core_get()) {
        if (allowAlreadyInitialized) {
            isInit = false; // someone else is holding the resource;
            return;
        }
        throw std::runtime_error("ERROR Relic already initialized.");
    }
    const int err_code = core_init();
    if (err_code != RLC_OK) {
        throw std::runtime_error(
            "ERROR cannot initialize  relic: core_init returned: "
            + std::to_string(err_code) + ".");
    }
    const int err_code_2 = pc_param_set_any();
    if (err_code_2 != RLC_OK) {
        throw std::runtime_error(
            "ERROR cannot initialize  relic: pc_param_set_any returned: "
            + std::to_string(err_code_2) + ".");
    }
    isInit = true;
}
relicResourceHandle::~relicResourceHandle()
{
    if (isInit) {
        core_clean();
    }
}
bool relicResourceHandle::isInitalized() const
{
    return isInit;
}
PairingGroup::PairingGroup()
{
    error_if_relic_not_init();
    bn_inits(grp_order);
    g1_get_ord(grp_order);
    isInit = true; // user needs to call setCurve after construction
}

PairingGroup::~PairingGroup()
{
    if (isInit) {
        bn_free(grp_order);
    }
}

ZR PairingGroup::randomZR() const
{
    ZR zr;
    ZR tt;
    bn_rand(tt.z, RLC_POS, bn_bits(grp_order));
    bn_mod(zr.z, tt.z, grp_order);
    return zr;
}

ZR PairingGroup::pseudoRandomZR(const sse::crypto::Prf<kPrfOutputSize>& prf,
                                const std::string& seed) const
{
    ZR                                  zr;
    ZR                                  tt;
    std::array<uint8_t, kPrfOutputSize> prf_out = prf.prf(seed);
    bn_read_bin(tt.z, prf_out.data(), kPrfOutputSize);
    //        bn_rand(tt.z, RLC_POS, bn_bits(grp_order));
    bn_mod(zr.z, tt.z, grp_order);
    return zr;
}

G1 PairingGroup::randomG1() const
{
    G1 g1;
    g1_rand(g1.g);
    return g1;
}

G2 PairingGroup::randomG2() const
{
    G2 g2;
    g2_rand(g2.g);
    return g2;
}

GT PairingGroup::randomGT() const
{
    GT gts;
    gt_rand(gts.g);
    return gts;
}


G1 PairingGroup::generatorG1() const
{
    G1 g1;
    g1_get_gen(g1.g);
    return g1;
}

G2 PairingGroup::generatorG2() const
{
    G2 g2;
    g2_get_gen(g2.g);
    return g2;
}

GT PairingGroup::generatorGT() const
{
    GT gt;
    gt_get_gen(gt.g);
    return gt;
}

ZR PairingGroup::neg(const ZR& r) const
{
    return -r;
}

ZR PairingGroup::inv(const ZR& r) const
{
    return r.inverse();
}
G1 PairingGroup::inv(const G1& g) const
{
    return -g;
}
G2 PairingGroup::inv(const G2& g) const
{
    return -g;
}
GT PairingGroup::inv(const GT& g) const
{
    return -g;
}

bool PairingGroup::ismember(ZR& zr)
{
    return zr.ismember();
}

bool PairingGroup::ismember(G1& g)
{
    return g.ismember(grp_order);
}

bool PairingGroup::ismember(G2& g)
{
    return g.ismember(grp_order); // add code to check
}


G2 PairingGroup::mul(const G2& g, const G2& h) const
{
    return g + h;
}

G2 PairingGroup::div(const G2& g, const G2& h) const
{
    return g + -h;
}

G2 PairingGroup::exp(const G2& g, const ZR& r) const
{
    // g ^ r == g * r OR scalar multiplication
    return power(g, r);
}

G2 PairingGroup::exp(const G2& g, const int& r) const
{
    // g ^ r == g * r OR scalar multiplication
    return power(g, ZR(r));
}

GT PairingGroup::pair(const G1& g, const G2& h) const
{
    return pairing(g, h);
}

GT PairingGroup::pair(const G2& h, const G1& g) const
{
    return pairing(g, h);
}

bool PairingGroup::ismember(GT& g)
{
    return g.ismember(grp_order); // add code to check
}

ZR PairingGroup::order() const
{
    return ZR(grp_order);
}

int PairingGroup::add(const int& g, const int& h) const
{
    return g + h;
}

ZR PairingGroup::add(const ZR& g, const ZR& h) const
{
    return g + h;
}

int PairingGroup::sub(const int& g, const int& h) const
{
    return g - h;
}

ZR PairingGroup::sub(const ZR& g, const ZR& h) const
{
    return g - h;
}

int PairingGroup::mul(const int& g, const int& h) const
{
    return g * h;
}


ZR PairingGroup::mul(const ZR& g, const ZR& h) const
{
    return g * h;
}

// mul for G1 & GT
G1 PairingGroup::mul(const G1& g, const G1& h) const
{
    return g + h;
}

GT PairingGroup::mul(const GT& g, const GT& h) const
{
    return g * h;
}

ZR PairingGroup::div(const int& g, const ZR& h) const
{
    return ZR(g) / h;
}

ZR PairingGroup::div(const ZR& g, const ZR& h) const
{
    return g / h;
}

// div for G1 & GT
G1 PairingGroup::div(const G1& g, const G1& h) const
{
    return g + -h;
}

GT PairingGroup::div(const GT& g, const GT& h) const
{
    return g / h;
}

int PairingGroup::div(const int& g, const int& h) const
{
    if (h == 0) {
        throw RelicDividByZero("divide by zero");
    }
    return g / h;
}

ZR PairingGroup::exp(const ZR& x, const int& y) const
{
    return power(x, y);
}

ZR PairingGroup::exp(const ZR& x, const ZR& y) const
{
    return power(x, y);
}

//// exp for G1 & GT
G1 PairingGroup::exp(const G1& g, const ZR& r) const
{
    // g ^ r == g * r OR scalar multiplication
    return power(g, r);
}

G1 PairingGroup::exp(const G1& g, const int& r) const
{
    // g ^ r == g * r OR scalar multiplication
    return power(g, ZR(r));
}

GT PairingGroup::exp(const GT& g, const ZR& r) const
{
    // g ^ r == g * r OR scalar multiplication
    return power(g, r);
}

GT PairingGroup::exp(const GT& g, const int& r) const
{
    // g ^ r == g * r OR scalar multiplication
    return power(g, ZR(r));
}

ZR PairingGroup::hashListToZR(const std::string& str) const
{
    bytes_vec b(str.begin(), str.end());
    return hashToZR(b);
}

ZR PairingGroup::hashListToZR(const bytes_vec& b) const
{
    ZR r = hashToZR(b);
    return r;
}
G1 PairingGroup::hashListToG1(const std::string& str) const
{
    bytes_vec b(str.begin(), str.end());
    return hashToG1(b);
}
G1 PairingGroup::hashListToG1(const bytes_vec& b) const
{
    G1 l = hashToG1(b);
    return l;
}

G2 PairingGroup::hashListToG2(const bytes_vec& b) const
{
    G2 l = hashToG2(b);
    return l;
}

// byte256 intToBits(const ZR &id){
//	byte256 zrlist;
//	int l=256;
//    int intval;
//    int j = l-1;
//
//    for(int i = 0; i < l; i++) {
//    	intval = bn_get_bit(id.z,i);
//    	/* store in reverse */
//    	zrlist[j-i] = intval;
//    }
//    return zrlist;
//}
// void setbit(std::vector<uint8_t> t,unsigned int i, bool b){
//	if(b){
//		t[i/sizeof(uint8_t)] |= 1 << (i%sizeof(uint8_t));
//	}else{
//		t[i/sizeof(uint8_t)] &= ~( 1 << (i%sizeof(uint8_t)));
//	}
//}
//
// std::vector<uint8_t> intToBits(const ZR &id){
//	std::vector<uint8_t> t(32);
//	int l=256;
//    int j = l-1;
//
//    for(int i = 0; i < l; i++) {
//    	bool bit =  bn_get_bit(id.z,i);
//    	/* store in reverse */
//    	setbit(t,j-i,bit);
//    }
//    return t;
//}
} // namespace relicxx
