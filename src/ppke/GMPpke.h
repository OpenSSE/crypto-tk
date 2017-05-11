/*
 * GMPpke.h
 *
 *  Created on: Dec 21, 2014
 *      Author: imiers
 */

#ifndef GMPPKE_H_
#define GMPPKE_H_

#include <array>

#include "forwardsec.h"
#include "util.h"

#include "hmac.hpp"
#include "hash.hpp"

namespace forwardsec{

constexpr static size_t kTagSize = 16;
typedef std::array<uint8_t, kTagSize> tag_type;

std::string tag2string(const tag_type& tag);
    
    
class Gmppke;
class PartialGmmppkeCT;
class GmppkePrivateKey;
class GmppkePublicKey: public  virtual  baseKey{
public:
	friend bool operator==(const GmppkePublicKey& x, const GmppkePublicKey& y){
		return  ((baseKey)x == (baseKey)y &&
				x.ppkeg1 == y.ppkeg1 && x.gqofxG1 == y.gqofxG1 &&
				x.gqofxG2 == y.gqofxG2);
	}
	friend bool operator!=(const GmppkePublicKey& x, const GmppkePublicKey& y){
		return !(x==y);
	}

protected:
	relicxx::G2 ppkeg1;

    std::array<relicxx::G1,2> gqofxG1;
    std::array<relicxx::G2,2> gqofxG2;
  
	friend class Gmppke;
};

 class GmppkePrivateKeyShare{
public:

	friend bool operator==(const GmppkePrivateKeyShare& x, const GmppkePrivateKeyShare& y){
		return  (x.sk1 == y.sk1 && x.sk2 == y.sk2 && x.sk3 == y.sk3 &&
				x.sk4 == y.sk4);
	}
	friend bool operator!=(const GmppkePrivateKeyShare& x, const GmppkePrivateKeyShare& y){
		return !(x==y);
	}
protected:
	relicxx::G2 sk1;
	relicxx::G2 sk2;
	relicxx::G2 sk3;
	tag_type sk4;

    friend class Gmppke;
	friend class GmppkePrivateKey;
};

 class GmppkePrivateKey{
public:
	friend bool operator==(const GmppkePrivateKey & l, const GmppkePrivateKey & r){
		return l.shares == r.shares;
	}
	friend bool operator!=(const GmppkePrivateKey & l, const GmppkePrivateKey & r){
		return !(l.shares == r.shares);
	}
	bool punctured() const{
		return shares.size() > 1;
	}

    bool isPuncturedOnTag(const tag_type &tag) const;

protected:
    std::vector<GmppkePrivateKeyShare> shares;

    friend class Gmppke;
 };

class GmppkeSecretParameters{
    
    friend bool operator==(const GmppkeSecretParameters & l, const GmppkeSecretParameters & r){
        return l.alpha == r.alpha && l.beta == r.beta && l.gamma == r.gamma && l.ry == r.ry;
    }
    friend bool operator!=(const GmppkeSecretParameters & l, const GmppkeSecretParameters & r){
        return !(l == r);
    }
        
    protected:
        relicxx::ZR alpha;
        relicxx::ZR beta;
        relicxx::ZR gamma;
        relicxx::ZR ry;

    friend class Gmppke;

};
    
class PartialGmmppkeCT{
public:
	 PartialGmmppkeCT(){};
		friend bool operator==(const PartialGmmppkeCT& x,const PartialGmmppkeCT& y){
			return x.ct2 == y.ct2 && x.ct3 == y.ct3 && x.tag == y.tag;
		}
		friend bool operator!=(const PartialGmmppkeCT& x, const PartialGmmppkeCT& y){
			return !(x==y);
		}

		/** Checks if you can decrypt a GMPfse ciphertext
		 *
		 * @param sk
		 * @param ct
		 * @return
		 */
		friend bool canDecrypt(const GmppkePrivateKey & sk,const PartialGmmppkeCT & ct);

protected:
	relicxx::G1 ct2;
	relicxx::G1 ct3;
    tag_type tag;

    friend class Gmppke;
};


template <typename T>
class GmmppkeCT: public PartialGmmppkeCT{
public:
    GmmppkeCT(){};
    GmmppkeCT(const  PartialGmmppkeCT & c) : PartialGmmppkeCT(c){}
protected:
    T ct1;
    
    friend bool operator==(const GmmppkeCT<T>& x,const GmmppkeCT<T>& y){
        return x.ct1 == y.ct1 && (PartialGmmppkeCT) x == (PartialGmmppkeCT) y;
    }
    friend bool operator!=(const GmmppkeCT<T>& x, const GmmppkeCT<T>& y){
        return !(x==y);
    }

    friend class Gmppke;
};


class Gmppke
{
public:

	Gmppke(){
//        std::cout << "Pairing group order: " << group.order() << std::endl;
    };
	~Gmppke() {};

	void keygen(GmppkePublicKey & pk, GmppkePrivateKey & sk, GmppkeSecretParameters &sp) const;

	void puncture(const GmppkePublicKey & pk, GmppkePrivateKey & sk, const tag_type & tag) const;

    PartialGmmppkeCT blind(const GmppkePublicKey & pk, const relicxx::ZR & s,  const tag_type & tag) const;
    PartialGmmppkeCT blind(const GmppkeSecretParameters & sp, const relicxx::ZR & s,  const tag_type & tag) const;

    relicxx::GT recoverBlind(const GmppkePrivateKey & sk, const PartialGmmppkeCT & ct ) const;

    template <typename T>
   	GmmppkeCT<T> encrypt(const GmppkePublicKey & pk,const T & M,const tag_type & tag) const
    {
        const relicxx::ZR s = group.randomZR();
        GmmppkeCT<T> ct = blind(pk,s,tag);
        
        auto hkdf = sse::crypto::HMac<sse::crypto::Hash>(tag.data(),tag.size());
        
        std::array<uint8_t, 12*FP_BYTES> gt_blind_bytes;
        group.exp(group.pair(pk.g2G1, pk.ppkeg1), s).getBytes(false, gt_blind_bytes.size(), gt_blind_bytes.data());
        
        T mask;
        hkdf.hmac(gt_blind_bytes.data(), gt_blind_bytes.size(), (uint8_t*) &mask, sizeof(mask));
        
        ct.ct1 = mask^M;
        return ct;
        
    }

    template <typename T>
   	GmmppkeCT<T> encrypt(const GmppkeSecretParameters & sp,const T & M,const tag_type & tag) const
    {
        const relicxx::ZR s = group.randomZR();
        GmmppkeCT<T> ct = blind(sp,s,tag);
        
        auto hkdf = sse::crypto::HMac<sse::crypto::Hash>(tag.data(),tag.size());
        
        std::array<uint8_t, 12*FP_BYTES> gt_blind_bytes;
        group.exp(group.generatorGT(), sp.alpha*sp.beta*s).getBytes(false, gt_blind_bytes.size(), gt_blind_bytes.data());

        T mask;
        hkdf.hmac(gt_blind_bytes.data(), gt_blind_bytes.size(), (uint8_t*) &mask, sizeof(mask));
        
        ct.ct1 = mask^M;
        return ct;
        
    }

    template <typename T>
    T decrypt(const GmppkePrivateKey & sk, const GmmppkeCT<T> & ct ) const
    {
        if (sk.isPuncturedOnTag(ct.tag)) {
            throw PuncturedCiphertext("cannot decrypt. The key is punctured on the following tag in the ciphertext: " + tag2string(ct.tag) + ".");
        }
        return decrypt_unchecked(sk,ct);
    }
    //For testing purposes only
    template <typename T>
    T decrypt_unchecked(const GmppkePrivateKey & sk, const GmmppkeCT<T> & ct ) const
    {
        std::vector<uint8_t> gt_blind_bytes = recoverBlind(sk,ct).getBytes(false);
        
        auto hkdf = sse::crypto::HMac<sse::crypto::Hash>(ct.tag.data(), ct.tag.size());
        
        T mask;
        hkdf.hmac(gt_blind_bytes.data(), gt_blind_bytes.size(), (uint8_t*)&mask, sizeof(mask));
        
        return mask^ct.ct1;
    }
    
    
private:
	relicxx::PairingGroup group;

    template <class T, size_t N>
	T  vx(const std::array<T,N> & gqofxG1, const tag_type & x) const{

        return LagrangeInterpInExponent<T,N>(group,group.hashListToZR(x),{{relicxx::ZR(0), relicxx::ZR(1)}},gqofxG1);

	}

	void keygenPartial(const relicxx::ZR & gamma,GmppkePublicKey & pk, GmppkePrivateKey & sk, GmppkeSecretParameters &sp) const;
//    GmppkePrivateKeyShare skgen(const GmppkePublicKey &pk,const relicxx::ZR & alpha ) const;
    GmppkePrivateKeyShare skgen(const GmppkeSecretParameters &sp,const relicxx::ZR & alpha ) const;
};

}
#endif /* GMPPKE_H_ */
