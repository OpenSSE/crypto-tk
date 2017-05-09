/*
 * GMPpke.h
 *
 *  Created on: Dec 21, 2014
 *      Author: imiers
 */

#ifndef GMPPKE_H_
#define GMPPKE_H_
//#include <cereal/types/base_class.hpp>
//#include <cereal/access.hpp>
//#include <cereal/types/vector.hpp>
//#include <cereal/types/string.hpp>

#include <array>

#include "forwardsec.h"
#include "util.h"

#include "hmac.hpp"
#include "hash.hpp"

namespace forwardsec{
class Gmppke;
class GMPfse;
class PartialGmmppkeCT;
class GmppkePrivateKey;
class GmppkePublicKey: public  virtual  baseKey{
public:
	friend bool operator==(const GmppkePublicKey& x, const GmppkePublicKey& y){
		return  ((baseKey)x == (baseKey)y &&
				x.ppkeg1 == y.ppkeg1 && x.d == y.d && x.gqofxG1 == y.gqofxG1 &&
				x.gqofxG2 == y.gqofxG2);
	}
	friend bool operator!=(const GmppkePublicKey& x, const GmppkePublicKey& y){
		return !(x==y);
	}
//	template <class Archive>
//	  void serialize( Archive & ar )
//	{
//		ar(::cereal::virtual_base_class<baseKey>(this),
//				ppkeg1,d,gqofxG1,gqofxG2);
//	}
protected:
	relicxx::G2 ppkeg1;
	unsigned int d;
	std::vector<relicxx::G1> gqofxG1;
	std::vector<relicxx::G2> gqofxG2;
//	friend class ::cereal::access;
	friend class Gmppke;
	friend class GMPfse;
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
	std::string sk4;
//	template <class Archive>
//	  void serialize( Archive & ar )
//	{
//		ar(sk1,sk2,sk3,sk4);
//	}
//	friend class cereal::access;
	friend class Gmppke;
	friend class GMPfse;
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
	/** Returns the tags, if any, that the key is punctured on.
	 *
	 * @param tags the tags
	 * @return the intersection
	 */
	std::vector<std::string> puncturedIntersect(const std::vector<std::string> & tags)const ;
protected:
	std::vector<GmppkePrivateKeyShare> shares;
//	template <class Archive>
//	  void serialize( Archive & ar )
//	{
//		ar(shares);
//	}
//	friend class cereal::access;
	friend class Gmppke;
	friend class GMPfse;
 };

class PartialGmmppkeCT{
public:
	 PartialGmmppkeCT(){};
		friend bool operator==(const PartialGmmppkeCT& x,const PartialGmmppkeCT& y){
			return x.ct2 == y.ct2 && x.ct3 == y.ct3 && x.tags == y.tags;
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
	std::vector<relicxx::G1> ct3;
    std::vector<std::string> tags;
//	template <class Archive>
//	void serialize( Archive & ar ){
//		ar(ct2,ct3,tags);
//	}
//	friend class cereal::access;
	friend class Gmppke;
	friend class GMPfse;
	friend class GMPfseCiphertext;
};

//class GmmppkeCT: public PartialGmmppkeCT{
//public:
//	GmmppkeCT(){};
//	GmmppkeCT(const  PartialGmmppkeCT & c) : PartialGmmppkeCT(c){}
//protected:
//	relicxx::GT ct1;
//	friend bool operator==(const GmmppkeCT& x,const GmmppkeCT& y){
//		return x.ct1 == y.ct1 && (PartialGmmppkeCT) x == (PartialGmmppkeCT) y;
//	}
//	friend bool operator!=(const GmmppkeCT& x, const GmmppkeCT& y){
//		return !(x==y);
//	}
////	template <class Archive>
////	void serialize( Archive & ar ){
////		ar(cereal::base_class<PartialGmmppkeCT>(this),ct1);
////	}
////	friend class cereal::access;
//	friend class Gmppke;
//	friend class GMPfse;
//};

    
//    typedef uint64_t index_type;

template <typename T>
class GmmppkeCT: public PartialGmmppkeCT{
public:
    GmmppkeCT(){};
    GmmppkeCT(const  PartialGmmppkeCT & c) : PartialGmmppkeCT(c){}
protected:
//    relicxx::GT ct1;
//    std::array<uint8_t, N> ct1;
    T ct1;
    
    friend bool operator==(const GmmppkeCT<T>& x,const GmmppkeCT<T>& y){
        return x.ct1 == y.ct1 && (PartialGmmppkeCT) x == (PartialGmmppkeCT) y;
    }
    friend bool operator!=(const GmmppkeCT<T>& x, const GmmppkeCT<T>& y){
        return !(x==y);
    }
    //	template <class Archive>
    //	void serialize( Archive & ar ){
    //		ar(cereal::base_class<PartialGmmppkeCT>(this),ct1);
    //	}
    //	friend class cereal::access;
    friend class Gmppke;
    friend class GMPfse;
};


class Gmppke
{
public:

	Gmppke(){};
	~Gmppke() {};

	void keygen(GmppkePublicKey & pk, GmppkePrivateKey & sk,const unsigned int & d = 1) const;

	void puncture(const GmppkePublicKey & pk, GmppkePrivateKey & sk, const std::string & tag) const;

	PartialGmmppkeCT blind(const GmppkePublicKey & pk, const relicxx::ZR & s,  const std::vector<std::string> & tags) const;

//	GmmppkeCT encrypt(const GmppkePublicKey & pk,const relicxx::GT & M,const std::vector<std::string> & tags) const;
 


	relicxx::GT recoverBlind(const GmppkePublicKey & pk, const GmppkePrivateKey & sk, const PartialGmmppkeCT & ct ) const;
//    relicxx::GT decrypt(const GmppkePublicKey & pk, const GmppkePrivateKey & sk, const GmmppkeCT & ct ) const;
//	//For testing purposes only
//	relicxx::GT decrypt_unchecked(const GmppkePublicKey & pk, const GmppkePrivateKey & sk, const GmmppkeCT & ct ) const;

    template <typename T>
   	GmmppkeCT<T> encrypt(const GmppkePublicKey & pk,const T & M,const std::vector<std::string> & tags) const
    {
        const relicxx::ZR s = group.randomZR();
        GmmppkeCT<T> ct = blind(pk,s,tags);
        auto hkdf = sse::crypto::HMac<sse::crypto::Hash>(tags[0]);
        
        std::vector<uint8_t> gt_blind_bytes = group.exp(group.pair(pk.g2G1, pk.ppkeg1), s).getBytes(false);
        T mask;
        hkdf.hmac(gt_blind_bytes.data(), gt_blind_bytes.size(), &mask, sizeof(mask));
        
        ct.ct1 = mask^M;
        return ct;
        
    }

    template <typename T>
    T decrypt(const GmppkePublicKey & pk, const GmppkePrivateKey & sk, const GmmppkeCT<T> & ct ) const
    {
        std::vector<std::string> intersect =sk.puncturedIntersect(ct.tags);
        if(intersect.size()>0){
            std::string duplicates = "";
            bool first = true;
            for(auto e: intersect){
                if(!first){
                    duplicates +=", ";
                }
                duplicates += e;
                first = false;
            }
            throw PuncturedCiphertext("cannot decrypt. The key is punctured on the following tags in the ciphertext: " + duplicates + ".");
        }
        return decrypt_unchecked(pk,sk,ct);
    }
    //For testing purposes only
    template <typename T>
    T decrypt_unchecked(const GmppkePublicKey & pk, const GmppkePrivateKey & sk, const GmmppkeCT<T> & ct ) const
    {
        std::vector<uint8_t> gt_blind_bytes = recoverBlind(pk,sk,ct).getBytes(false);
        auto hkdf = sse::crypto::HMac<sse::crypto::Hash>(ct.tags[0]);
        
        T mask;
        hkdf.hmac(gt_blind_bytes.data(), gt_blind_bytes.size(), &mask, sizeof(mask));
        
        return mask^ct.ct1;
    }
    
    
private:
	relicxx::PairingGroup group;
//	G1 vG1(const std::vector<G1> & gqofxG1, const ZR & x) const;
//	G2 vG2(const std::vector<G2> & gqofxG2, const ZR & x) const;
	template <class T>
	T  vx(const std::vector<T> & gqofxG1, const std::string & x) const{
	    std::vector<relicxx::ZR> xcords;
	    int size = (int)gqofxG1.size();
	    for(int i=0;i<size;i++){
	    	relicxx::ZR xcord = i;
	        xcords.push_back(xcord);
	    }
	    return LagrangeInterpInExponent(group,group.hashListToZR(x),xcords,gqofxG1);

	}

	void keygenPartial(const relicxx::ZR & gamma,GmppkePublicKey & pk, GmppkePrivateKey & sk,const unsigned int & d=1) const;
	GmppkePrivateKeyShare skgen(const GmppkePublicKey &pk,const relicxx::ZR & alpha ) const;
	friend class GMPfse;
};

}
// cereal can't find the serialization function if we don't do this.
// this has to be outside of the namespace.
//namespace cereal
//{
// template <class Archive>
// struct specialize<Archive, forwardsec::GmppkePublicKey, cereal::specialization::member_serialize> {};
// // cereal no longer has any ambiguity when serializing MyDerived
//}
#endif /* GMPPKE_H_ */
