//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2017 Raphael Bost
//
// This file is part of libsse_crypto.
//
// libsse_crypto is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// libsse_crypto is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with libsse_crypto.  If not, see <http://www.gnu.org/licenses/>.
//

#include "puncturable_enc.hpp"

#include "ppke/GMPpke.hpp"
#include "prf.hpp"

namespace sse {

namespace crypto {

#define PPKE ppke_

static_assert(punct::kCiphertextSize == GmmppkeCT<uint64_t>::kCTByteSize,
              "Invalid Ciphertext Size");
static_assert(punct::kKeyShareSize == GmppkePrivateKeyShare::kByteSize,
              "Invalid Key share Size");

class PuncturableEncryption::PEncImpl
{
public:
    explicit PEncImpl(punct::master_key_type&& key);

    punct::ciphertext_type encrypt(const uint64_t         m,
                                   const punct::tag_type& tag);
    punct::key_share_type  initial_keyshare(const size_t d);
    punct::key_share_type  inc_puncture(const size_t           d,
                                        const punct::tag_type& tag);

private:
    const Gmppke ppke_{};

    sse::crypto::GmppkeSecretParameters        sp_;
    const sse::crypto::Prf<kPPKEPrfOutputSize> master_prf_;

    static_assert(punct::kMasterKeySize
                      == sse::crypto::Prf<kPPKEPrfOutputSize>::kKeySize,
                  "PPKE: Invalid master key size");
};


PuncturableEncryption::PEncImpl::PEncImpl(punct::master_key_type&& key)
    : master_prf_(std::move(key))
{
    PPKE.paramgen(master_prf_, sp_);
}

punct::ciphertext_type PuncturableEncryption::PEncImpl::encrypt(
    const uint64_t         m,
    const punct::tag_type& tag)
{
    GmmppkeCT<uint64_t> ct = PPKE.encrypt(sp_, m, tag);

    punct::ciphertext_type ct_bytes;
    ct.writeBytes(ct_bytes.data());

    return ct_bytes;
}


punct::key_share_type PuncturableEncryption::PEncImpl::inc_puncture(
    const size_t           d,
    const punct::tag_type& tag)
{
    GmppkePrivateKeyShare ks = PPKE.skShareGen(master_prf_, sp_, d, tag);
    punct::key_share_type ks_bytes;
    ks.writeBytes(ks_bytes.data());

    return ks_bytes;
}

punct::key_share_type PuncturableEncryption::PEncImpl::initial_keyshare(
    const size_t d)
{
    GmppkePrivateKeyShare ks = PPKE.sk0Gen(master_prf_, sp_, d);
    punct::key_share_type ks_bytes;
    ks.writeBytes(ks_bytes.data());

    return ks_bytes;
}

PuncturableEncryption::PuncturableEncryption(punct::master_key_type&& key)
    : penc_imp_(new PEncImpl(std::move(key)))
{
}

// NOLINTNEXTLINE(modernize-use-equals-default)
PuncturableEncryption::~PuncturableEncryption()
{
}

punct::ciphertext_type PuncturableEncryption::encrypt(
    const uint64_t         m,
    const punct::tag_type& tag)
{
    return penc_imp_->encrypt(m, tag);
}

punct::key_share_type PuncturableEncryption::initial_keyshare(const size_t d)
{
    return penc_imp_->initial_keyshare(d);
}

punct::key_share_type PuncturableEncryption::inc_puncture(
    const size_t           d,
    const punct::tag_type& tag)
{
    return penc_imp_->inc_puncture(d, tag);
}


class PuncturableDecryption::PDecImpl
{
public:
    explicit PDecImpl(const punct::punctured_key_type& punctured_key);

    bool is_punctured_on_tag(const punct::tag_type& tag);
    bool decrypt(const punct::ciphertext_type& ct_bytes, uint64_t& m) const;

private:
    const Gmppke ppke_{};

    GmppkePrivateKey sk_;
};

PuncturableDecryption::PDecImpl::PDecImpl(
    const punct::punctured_key_type& punctured_key)
{
    std::vector<GmppkePrivateKeyShare> shares(punctured_key.size());
    for (size_t i = 0; i < punctured_key.size(); i++) {
        shares[i] = GmppkePrivateKeyShare(punctured_key[i].data());
    }

    sk_ = GmppkePrivateKey(shares);
}

bool PuncturableDecryption::PDecImpl::decrypt(
    const punct::ciphertext_type& ct_bytes,
    uint64_t&                     m) const
{
    return PPKE.decrypt(sk_, GmmppkeCT<uint64_t>(ct_bytes.data()), m);
}


PuncturableDecryption::PuncturableDecryption(
    const punct::punctured_key_type& punctured_key)
    : pdec_imp_(new PDecImpl(punctured_key))
{
}

// NOLINTNEXTLINE(modernize-use-equals-default)
PuncturableDecryption::~PuncturableDecryption()
{
}


bool PuncturableDecryption::decrypt(const punct::ciphertext_type& ct,
                                    uint64_t&                     m)
{
    return pdec_imp_->decrypt(ct, m);
}


} // namespace crypto
} // namespace sse
