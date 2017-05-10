
#include <assert.h>
#include <unordered_set>
#include "GMPpke.h"
#include "util.h"


namespace forwardsec{

using namespace std;
using namespace relicxx;
//static const string  NULLTAG = "whoever wishes to keep a secret, must hide from us that he possesses one.-- Johann Wolfgang von Goethe"; // the reserved tag

static const tag_type NULLTAG = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
    
    
std::string tag2string(const tag_type& tag)
{
    return string((char *)tag.data(),tag.size());
}

using namespace std;
    
bool GmppkePrivateKey::isPuncturedOnTag(const tag_type &tag) const
{
    for(auto share : shares){

        if(share.sk4 == tag){
            return true;
        }
    }
    return false;
}

void Gmppke::keygen(GmppkePublicKey & pk, GmppkePrivateKey & sk) const
{
   GmppkePublicKey bpk;
   const ZR alpha = group.randomZR();
   bpk.gG1 = group.randomG1();
   bpk.gG2 = group.randomG2();
   const ZR beta = group.randomZR();
   bpk.g2G1 = group.exp(bpk.gG1, beta);
   bpk.g2G2 = group.exp(bpk.gG2, beta);
   pk.gG1 = bpk.gG1;
   pk.gG2 = bpk.gG2;
   pk.g2G1 = bpk.g2G1;
   pk.g2G2 = bpk.g2G2;
   keygenPartial(alpha,pk,sk);
}
    
void Gmppke::keygenPartial(const ZR & alpha, GmppkePublicKey & pk, GmppkePrivateKey & sk) const
{
    pk.ppkeg1 =  group.exp(pk.gG2,alpha);

    // Select a random polynomial of degree d subject to q(0)= beta. We do this
    // by selecting d+1 points. Because we don't actually  care about the
    // polynomial, only g^q(x), we merely select points as (x,g^q(x)).

    array<ZR,2> polynomial_xcordinates;

    // the first point is (x=0,y=beta) so  x=0, g^beta.
    polynomial_xcordinates[0] = ZR(0);
    pk.gqofxG1[0] = pk.g2G1; // g^beta
    pk.gqofxG2[0] = pk.g2G2; // g^beta

    // the next d points' y values  are random
    // we use x= 1...d because this has the side effect
    // of easily computing g^q(0).... g^q(d).
    // here d = 1
    
    
    const ZR ry = group.randomZR();

    polynomial_xcordinates[1] = ZR(1);
    pk.gqofxG1[1] = group.exp(pk.gG1,ry);
    pk.gqofxG2[1] = group.exp(pk.gG2,ry);

    assert(polynomial_xcordinates.size()==pk.gqofxG1.size());

    // Sanity check that Lagrange interpolation works to get us g^beta on q(0).
    assert(pk.g2G1 == LagrangeInterpInExponent<G1>(group,0,polynomial_xcordinates,pk.gqofxG1));
    assert(pk.g2G2 == LagrangeInterpInExponent<G2>(group,0,polynomial_xcordinates,pk.gqofxG2));


    sk.shares.push_back(skgen(pk,alpha));

    return;
}
GmppkePrivateKeyShare Gmppke::skgen(const GmppkePublicKey &pk,const ZR & alpha  ) const{
	GmppkePrivateKeyShare share;
    share.sk4 = NULLTAG;
    const ZR r = group.randomZR();
    share.sk1 = group.exp(pk.g2G2, group.add(r,alpha));
    G2 vofx = vx(pk.gqofxG2,NULLTAG); // calculate v(t0).
    share.sk2 = group.exp(vofx, r);// v(t0)^r
    share.sk3 = group.exp(pk.gG2, r);
    return share;
}

void Gmppke::puncture(const GmppkePublicKey & pk, GmppkePrivateKey & sk, const tag_type & tag) const{

	if(tag == NULLTAG){
//		throw invalid_argument("Invalid tag "+tag +". The tag " + NULLTAG + " is reserved and cannot be used.");
		throw invalid_argument("Invalid tag: the NULLTAG is reserved and cannot be used.");        
	}
    GmppkePrivateKeyShare skentryn;
    GmppkePrivateKeyShare & skentry0 = sk.shares.at(0);

    const ZR r0 = group.randomZR();
    const ZR r1 = group.randomZR();
    const ZR lambda = group.randomZR();

    assert(skentry0.sk4 == NULLTAG);

    skentry0.sk1 = group.mul(skentry0.sk1,group.exp(pk.g2G2,group.sub(r0,lambda))); // sk1 * g2g2^{r0- lambda}
    const G2 vofx = vx(pk.gqofxG2,NULLTAG);
    skentry0.sk2 = group.mul(skentry0.sk2,group.exp(vofx,r0));  // sk2 * V(t0)^r0
    skentry0.sk3 = group.mul(skentry0.sk3,group.exp(pk.gG2,r0));  // sk3 * g2G2^r0

    skentryn.sk1=group.exp(pk.g2G2,group.add(r1,lambda));  // gG2 ^ (r1+lambda)
    const G2 vofx2 = vx(pk.gqofxG2,tag);
    skentryn.sk2 = group.exp(vofx2,r1); // V(tag) ^ r1
    skentryn.sk3 = group.exp(pk.gG2,r1);  // G^ r1
    skentryn.sk4 = tag;

    sk.shares.push_back(skentryn);
}



PartialGmmppkeCT Gmppke::blind(const GmppkePublicKey & pk, const ZR & s, const tag_type & tag ) const
{
    PartialGmmppkeCT  ct;
    ct.ct2 = group.exp(pk.gG1, s);
    G1 vofx = vx(pk.gqofxG1,tag);
    ct.ct3 = group.exp(vofx, s);

    ct.tag = tag;
    return ct;
}



GT Gmppke::recoverBlind(const GmppkePublicKey & pk, const GmppkePrivateKey & sk, const PartialGmmppkeCT & ct) const
{
    ZR ctTag = group.hashListToZR(ct.tag);
    
    const unsigned int numshares = (unsigned int)sk.shares.size();
    

    // Compute w_i coefficients for recovery
    vector<GT> z(numshares);
    
    
    relicResourceHandle h(true);
#pragma omp parallel for private(h) firstprivate(shareTags)
    for (unsigned int i = 0; i < numshares; i++)
    {
        const GmppkePrivateKeyShare & s0 = sk.shares.at(i);
        ZR currentTag = group.hashListToZR(s0.sk4);
        
        
        ZR w0 = LagrangeBasisCoefficients<2>(group,0,0, {ctTag, currentTag});
        const ZR wstar = LagrangeBasisCoefficients<2>(group,1,0,{ctTag, currentTag});

        
        G1 ct3prod_j;

        ct3prod_j = group.mul(ct3prod_j, group.exp(ct.ct3,w0));
            
        GT denominator = group.mul(group.pair(ct3prod_j, s0.sk3), group.pair(group.exp(ct.ct2,wstar), s0.sk2));
        GT nominator = group.pair(ct.ct2, s0.sk1);

        z.at(i)=group.div(nominator, denominator);
    }
    
    GT zprod;
    for (unsigned int i = 0; i < numshares; i++)
    {
        zprod = group.mul(zprod, z.at(i));
    }
    return zprod;
}

}
