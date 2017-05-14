//
//  ppke.cpp
//  libsse_crypto
//
//  Created by Raphael Bost on 14/05/2017.
//  Copyright © 2017 VSSE project. All rights reserved.
//

#include "puncturable_enc.hpp"

#include "prf.hpp"
#include "ppke/GMPpke.h"

namespace sse
{
    
    namespace crypto
    {
//        static relicxx::relicResourceHandle *handle__;
//        class PpkeHandler
//        {
//        public:
//            PpkeHandler() /*handle_(true),*/ 
//            {
//                if (handle__ == NULL) {
//                    handle__ = new relicxx::relicResourceHandle(true);
//                }
//            }
//            
//            ~PpkeHandler()
//            {
//            }
//            
//            
//            const Gmppke& get_ppke() const { return ppke_; }
//            
//        private:
////            const relicxx::relicResourceHandle handle_;
//            const sse::crypto::Gmppke ppke_;
//        };
//        
//        
//        PpkeHandler ppke_handler__;

#define PPKE ppke_
        
        static_assert(punct::kCiphertextSize == GmmppkeCT<uint64_t>::kByteSize, "Invalid Ciphertext Size");
        static_assert(punct::kKeyShareSize == GmppkePrivateKeyShare::kByteSize, "Invalid Key share Size");
        
        class PuncturableEncryption::PEncImpl
        {
        public:
            PEncImpl(const punct::master_key_type& key);
            
            punct::ciphertext_type encrypt(const uint64_t m, const punct::tag_type &tag);
            punct::key_share_type initial_keyshare(const size_t d);
            punct::key_share_type inc_puncture(const size_t d, const punct::tag_type &tag);

        private:
            const Gmppke ppke_;
        
            sse::crypto::GmppkeSecretParameters sp_;
            const sse::crypto::Prf<kPPKEPrfOutputSize> master_prf_;
        };
        

        PuncturableEncryption::PEncImpl::PEncImpl(const punct::master_key_type& key) : master_prf_(key.data(), punct::kMasterKeySize)
        {
            PPKE.paramgen(master_prf_, sp_);
        }
        
        punct::ciphertext_type PuncturableEncryption::PEncImpl::encrypt(const uint64_t m, const punct::tag_type &tag)
        {
            GmmppkeCT<uint64_t> ct = PPKE.encrypt(sp_, m, tag);
            
            punct::ciphertext_type ct_bytes;
            ct.writeBytes(ct_bytes.data());
            
            return ct_bytes;
        }

        
        punct::key_share_type PuncturableEncryption::PEncImpl::inc_puncture(const size_t d, const punct::tag_type &tag)
        {
            GmppkePrivateKeyShare ks = PPKE.skShareGen(master_prf_, sp_, d, tag);
            punct::key_share_type ks_bytes;
            ks.writeBytes(ks_bytes.data());

            return ks_bytes;
        }

        punct::key_share_type PuncturableEncryption::PEncImpl::initial_keyshare(const size_t d)
        {
            GmppkePrivateKeyShare ks = PPKE.sk0Gen(master_prf_, sp_, d);
            punct::key_share_type ks_bytes;
            ks.writeBytes(ks_bytes.data());
            
            return ks_bytes;
        }

        PuncturableEncryption::PuncturableEncryption(const punct::master_key_type& key) : penc_imp_(new PEncImpl(key))
        {
        }
        
        PuncturableEncryption::~PuncturableEncryption()
        {
            delete penc_imp_;
        }
        
        punct::ciphertext_type PuncturableEncryption::encrypt(const uint64_t m, const punct::tag_type &tag)
        {
            return penc_imp_->encrypt(m, tag);
        }
        
        punct::key_share_type PuncturableEncryption::initial_keyshare(const size_t d)
        {
            return penc_imp_->initial_keyshare(d);
        }
        
        punct::key_share_type PuncturableEncryption::inc_puncture(const size_t d, const punct::tag_type &tag)
        {
            return penc_imp_->inc_puncture(d, tag);
        }
        
        
        class PuncturableDecryption::PDecImpl
        {
        public:
            PDecImpl(const punct::punctured_key_type& punctured_key);
            
            bool is_punctured_on_tag(const punct::tag_type &tag);
            bool decrypt(const punct::ciphertext_type &ct, uint64_t &m) const;
            
        private:
            const Gmppke ppke_;

            GmppkePrivateKey sk_;
        };

        PuncturableDecryption::PDecImpl::PDecImpl(const punct::punctured_key_type& punctured_key)
        {
            std::vector<GmppkePrivateKeyShare> shares(punctured_key.size());
            for (size_t i = 0; i < punctured_key.size(); i++) {
                shares[i] = GmppkePrivateKeyShare(punctured_key[i].data());
            }
            
            sk_ = GmppkePrivateKey(std::move(shares));
        }

        bool PuncturableDecryption::PDecImpl::decrypt(const punct::ciphertext_type &ct_bytes, uint64_t &m) const
        {
            return PPKE.decrypt(sk_, GmmppkeCT<uint64_t>(ct_bytes.data()), m);
        }
        
        
        PuncturableDecryption::PuncturableDecryption(const punct::punctured_key_type& punctured_key) : pdec_imp_(new PDecImpl(punctured_key))
        {
        }
        
        PuncturableDecryption::~PuncturableDecryption()
        {
            delete pdec_imp_;
        }
        
        
        bool PuncturableDecryption::decrypt(const punct::ciphertext_type &ct, uint64_t &m)
        {
            return pdec_imp_->decrypt(ct, m);
        }
        

    }
}
