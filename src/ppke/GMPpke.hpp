/*
 * GMPpke.hpp
 *
 *  Created on: Dec 21, 2014
 *      Author: imiers
 */

#ifndef GMPPKE_H_
#define GMPPKE_H_

#include "ppke/util.hpp"
#include "relic_wrapper/relic_api.h"

#include <sse/crypto/hash.hpp>
#include <sse/crypto/hmac.hpp>
#include <sse/crypto/key.hpp>
#include <sse/crypto/prf.hpp>

#include <array>
#include <utility>

namespace sse {

namespace crypto {

constexpr static size_t kTagSize                 = 16;
constexpr unsigned int  kPPKEStatisticalSecurity = 32;
constexpr static size_t kPPKEPrfOutputSize
    = relicxx::PairingGroup::kPrfOutputSize;

// cppcheck-suppress constStatement
using PPKE_HKDF = sse::crypto::HMac<sse::crypto::Hash, 12 * RLC_FP_BYTES>;

using tag_type = std::array<uint8_t, kTagSize>;

std::string tag2string(const tag_type& tag);

class BadCiphertext : public std::invalid_argument
{
public:
    explicit BadCiphertext(std::string const& error)
        : std::invalid_argument(error)
    {
    }
};

class PuncturedCiphertext : public BadCiphertext
{
public:
    explicit PuncturedCiphertext(std::string const& error)
        : BadCiphertext(error)
    {
    }
};


class baseKey
{
public:
    relicxx::G1 gG1;
    relicxx::G2 gG2;
    relicxx::G1 g2G1;
    relicxx::G2 g2G2;
    friend bool operator==(const baseKey& x, const baseKey& y)
    {
        return (x.gG1 == y.gG1 && x.gG2 == y.gG2 && x.g2G1 == y.g2G1
                && x.g2G2 == y.g2G2);
    }
    friend bool operator!=(const baseKey& x, const baseKey& y)
    {
        return !(x == y);
    }
};


class Gmppke;
class PartialGmmppkeCT;
class GmppkePrivateKey;
class GmppkePublicKey : public baseKey
{
public:
    friend bool operator==(const GmppkePublicKey& x, const GmppkePublicKey& y)
    {
        return (static_cast<const baseKey&>(x) == static_cast<const baseKey&>(y)
                && x.ppkeg1 == y.ppkeg1 && x.gqofxG1 == y.gqofxG1
                && x.gqofxG2 == y.gqofxG2);
    }
    friend bool operator!=(const GmppkePublicKey& x, const GmppkePublicKey& y)
    {
        return !(x == y);
    }

protected:
    relicxx::G2 ppkeg1;

    std::array<relicxx::G1, 2> gqofxG1;
    std::array<relicxx::G2, 2> gqofxG2;

    friend class Gmppke;
};

class GmppkePrivateKeyShare
{
public:
    static constexpr size_t kByteSize
        = 3 * relicxx::G2::kCompactByteSize + kTagSize;

    GmppkePrivateKeyShare() = default;

    explicit GmppkePrivateKeyShare(const uint8_t* bytes)
        : sk1(bytes, true), sk2(bytes + relicxx::G2::kCompactByteSize, true),
          sk3(bytes + 2 * relicxx::G2::kCompactByteSize, true)
    {
        ::memcpy(
            sk4.data(), bytes + 3 * relicxx::G2::kCompactByteSize, kTagSize);
    }


    friend bool operator==(const GmppkePrivateKeyShare& x,
                           const GmppkePrivateKeyShare& y)
    {
        return (x.sk1 == y.sk1 && x.sk2 == y.sk2 && x.sk3 == y.sk3
                && x.sk4 == y.sk4);
    }
    friend bool operator!=(const GmppkePrivateKeyShare& x,
                           const GmppkePrivateKeyShare& y)
    {
        return !(x == y);
    }

    void writeBytes(uint8_t* bytes) const
    {
        sk1.writeBytes(bytes, true); // compress
        sk2.writeBytes(bytes + relicxx::G2::kCompactByteSize, true);
        sk3.writeBytes(bytes + 2 * relicxx::G2::kCompactByteSize, true);
        ::memcpy(
            bytes + 3 * relicxx::G2::kCompactByteSize, sk4.data(), sk4.size());
    }

    inline const tag_type& get_tag() const
    {
        return sk4;
    }

protected:
    relicxx::G2 sk1;
    relicxx::G2 sk2;
    relicxx::G2 sk3;
    tag_type    sk4;

    friend class Gmppke;
    friend class GmppkePrivateKey;
};

class GmppkePrivateKey
{
public:
    GmppkePrivateKey() = default;

    // cppcheck-suppress passedByValue
    explicit GmppkePrivateKey(std::vector<GmppkePrivateKeyShare> s)
        : shares(std::move(s))
    {
    }

    friend bool operator==(const GmppkePrivateKey& l, const GmppkePrivateKey& r)
    {
        return l.shares == r.shares;
    }
    friend bool operator!=(const GmppkePrivateKey& l, const GmppkePrivateKey& r)
    {
        return !(l.shares == r.shares);
    }
    bool punctured() const
    {
        return shares.size() > 1;
    }

    bool isPuncturedOnTag(const tag_type& tag) const;

protected:
    std::vector<GmppkePrivateKeyShare> shares;

    friend class Gmppke;
};

class GmppkeSecretParameters
{
    friend bool operator==(const GmppkeSecretParameters& l,
                           const GmppkeSecretParameters& r)
    {
        return l.alpha == r.alpha && l.beta == r.beta && l.ry == r.ry;
    }
    friend bool operator!=(const GmppkeSecretParameters& l,
                           const GmppkeSecretParameters& r)
    {
        return !(l == r);
    }

protected:
    relicxx::ZR alpha;
    relicxx::ZR beta;
    relicxx::ZR ry;

    friend class Gmppke;
};

class PartialGmmppkeCT
{
public:
    static constexpr size_t kByteSize
        = 2 * relicxx::G1::kCompactByteSize + kTagSize;

    PartialGmmppkeCT() = default;

    explicit PartialGmmppkeCT(const uint8_t* bytes)
        : ct2(bytes, true), ct3(bytes + relicxx::G1::kCompactByteSize, true)
    {
        ::memcpy(
            tag.data(), bytes + 2 * relicxx::G1::kCompactByteSize, kTagSize);
    }

    friend bool operator==(const PartialGmmppkeCT& x, const PartialGmmppkeCT& y)
    {
        return x.ct2 == y.ct2 && x.ct3 == y.ct3 && x.tag == y.tag;
    }
    friend bool operator!=(const PartialGmmppkeCT& x, const PartialGmmppkeCT& y)
    {
        return !(x == y);
    }

    void writeBytes(uint8_t* bytes) const
    {
        ct2.writeBytes(bytes, true); // compress
        ct3.writeBytes(bytes + relicxx::G1::kCompactByteSize, true);
        ::memcpy(
            bytes + 2 * relicxx::G1::kCompactByteSize, tag.data(), tag.size());
    }

protected:
    relicxx::G1 ct2;
    relicxx::G1 ct3;
    tag_type    tag;

    friend class Gmppke;
};


template<typename T>
class GmmppkeCT : public PartialGmmppkeCT
{
public:
    static constexpr size_t kCTByteSize
        = PartialGmmppkeCT::kByteSize + sizeof(T);

    GmmppkeCT() = default;

    explicit GmmppkeCT(const uint8_t* bytes)
        : PartialGmmppkeCT(bytes + sizeof(T))
    {
        ::memcpy(&ct1, bytes, sizeof(T));
    }
    explicit GmmppkeCT(const PartialGmmppkeCT& c) : PartialGmmppkeCT(c), ct1(0)
    {
    }

    void writeBytes(uint8_t* bytes) const
    {
        ::memcpy(bytes, &ct1, sizeof(T));
        PartialGmmppkeCT::writeBytes(bytes + sizeof(T));
    }

protected:
    T ct1;

    friend bool operator==(const GmmppkeCT<T>& x, const GmmppkeCT<T>& y)
    {
        return x.ct1 == y.ct1
               && static_cast<const PartialGmmppkeCT&>(x)
                      == static_cast<const PartialGmmppkeCT&>(y);
    }
    friend bool operator!=(const GmmppkeCT<T>& x, const GmmppkeCT<T>& y)
    {
        return !(x == y);
    }

    friend class Gmppke;
};


class Gmppke
{
public:
    static constexpr uint8_t kPRFKeySize = 32; // 256 bits
    static const tag_type    NULLTAG;

    Gmppke()  = default;
    ~Gmppke() = default;

    void keygen(GmppkePublicKey&        pk,
                GmppkePrivateKey&       sk,
                GmppkeSecretParameters& sp) const;
    void keygen(Key<kPRFKeySize>&&      prf_key,
                GmppkePublicKey&        pk,
                GmppkePrivateKey&       sk,
                GmppkeSecretParameters& sp) const;
    void keygen(const sse::crypto::Prf<kPPKEPrfOutputSize>& prf,
                GmppkePublicKey&                            pk,
                GmppkePrivateKey&                           sk,
                GmppkeSecretParameters&                     sp) const;

    void paramgen(const sse::crypto::Prf<kPPKEPrfOutputSize>& prf,
                  GmppkeSecretParameters&                     sp) const;

    void puncture(const GmppkePublicKey& pk,
                  GmppkePrivateKey&      sk,
                  const tag_type&        tag) const;

    PartialGmmppkeCT blind(const GmppkePublicKey& pk,
                           const relicxx::ZR&     s,
                           const tag_type&        tag) const;
    PartialGmmppkeCT blind(const GmppkeSecretParameters& sp,
                           const relicxx::ZR&            s,
                           const tag_type&               tag) const;

    relicxx::GT recoverBlind(const GmppkePrivateKey& sk,
                             const PartialGmmppkeCT& ct) const;

    template<typename T>
    GmmppkeCT<T> encrypt(const GmppkePublicKey& pk,
                         const T&               M,
                         const tag_type&        tag) const
    {
        const relicxx::ZR s  = group.randomZR();
        GmmppkeCT<T>      ct = GmmppkeCT<T>(blind(pk, s, tag));

        auto arr = tag;

        sse::crypto::HMac<sse::crypto::Hash, kTagSize> hkdf(
            sse::crypto::Key<kTagSize>(arr.data()));

        std::array<uint8_t, 12 * RLC_FP_BYTES> gt_blind_bytes;
        group.exp(group.pair(pk.g2G1, pk.ppkeg1), s)
            .getBytes(false, gt_blind_bytes.size(), gt_blind_bytes.data());

        T mask;
        hkdf.hmac(gt_blind_bytes.data(),
                  gt_blind_bytes.size(),
                  reinterpret_cast<uint8_t*>(&mask),
                  sizeof(mask));

        ct.ct1 = mask ^ M;
        return ct;
    }

    template<typename T>
    GmmppkeCT<T> encrypt(const GmppkeSecretParameters& sp,
                         const T&                      M,
                         const tag_type&               tag) const
    {
        const relicxx::ZR s  = group.randomZR();
        GmmppkeCT<T>      ct = GmmppkeCT<T>(blind(sp, s, tag));

        auto                                           arr = tag;
        sse::crypto::HMac<sse::crypto::Hash, kTagSize> hkdf(
            sse::crypto::Key<kTagSize>(arr.data()));

        std::array<uint8_t, 12 * RLC_FP_BYTES> gt_blind_bytes;
        group.exp(group.generatorGT(), sp.alpha * sp.beta * s)
            .getBytes(false, gt_blind_bytes.size(), gt_blind_bytes.data());

        T mask;
        hkdf.hmac(gt_blind_bytes.data(),
                  gt_blind_bytes.size(),
                  reinterpret_cast<uint8_t*>(&mask),
                  sizeof(mask));

        ct.ct1 = mask ^ M;
        return ct;
    }

    template<typename T>
    T decrypt(const GmppkePrivateKey& sk, const GmmppkeCT<T>& ct) const
    {
        if (sk.isPuncturedOnTag(ct.tag)) {
            throw PuncturedCiphertext("cannot decrypt. The key is punctured on "
                                      "the following tag in the ciphertext: "
                                      + tag2string(ct.tag) + ".");
        }
        return decrypt_unchecked(sk, ct);
    }
    template<typename T>
    bool decrypt(const GmppkePrivateKey& sk, const GmmppkeCT<T>& ct, T& m) const
    {
        if (sk.isPuncturedOnTag(ct.tag)) {
            return false;
        }
        m = decrypt_unchecked(sk, ct);

        return true;
    }

    // For testing purposes only
    template<typename T>
    T decrypt_unchecked(const GmppkePrivateKey& sk,
                        const GmmppkeCT<T>&     ct) const
    {
        std::vector<uint8_t> gt_blind_bytes
            = recoverBlind(sk, ct).getBytes(false);

        auto                                           arr = ct.tag;
        sse::crypto::HMac<sse::crypto::Hash, kTagSize> hkdf(
            sse::crypto::Key<kTagSize>(arr.data()));

        T mask;
        hkdf.hmac(gt_blind_bytes.data(),
                  gt_blind_bytes.size(),
                  reinterpret_cast<uint8_t*>(&mask),
                  sizeof(mask));

        return mask ^ ct.ct1;
    }

    GmppkePrivateKeyShare sk0Gen(
        const sse::crypto::Prf<kPPKEPrfOutputSize>& prf,
        const GmppkeSecretParameters&               sp,
        size_t                                      d) const;
    GmppkePrivateKeyShare skShareGen(
        const sse::crypto::Prf<kPPKEPrfOutputSize>& prf,
        const GmppkeSecretParameters&               sp,
        size_t                                      d,
        const tag_type&                             tag) const;

private:
    relicxx::PairingGroup group;

    template<class T, size_t N>
    T vx(const std::array<T, N>& gqofxG1, const tag_type& x) const
    {
        return LagrangeInterpInExponent<T, N>(
            group,
            group.hashListToZR(x),
            {{relicxx::ZR(0), relicxx::ZR(1)}},
            gqofxG1);
    }

    void keygenPartial(const relicxx::ZR&            alpha,
                       GmppkePublicKey&              pk,
                       GmppkePrivateKey&             sk,
                       const GmppkeSecretParameters& sp) const;
    void keygenPartial(const sse::crypto::Prf<kPPKEPrfOutputSize>& prf,
                       const relicxx::ZR&                          alpha,
                       GmppkePublicKey&                            pk,
                       GmppkePrivateKey&                           sk,
                       const GmppkeSecretParameters&               sp) const;

    GmppkePrivateKeyShare skgen(const GmppkeSecretParameters& sp) const;
    GmppkePrivateKeyShare skgen(const sse::crypto::Prf<kPPKEPrfOutputSize>& prf,
                                const GmppkeSecretParameters& sp) const;
};

} // namespace crypto
} // namespace sse
#endif /* GMPPKE_H_ */
