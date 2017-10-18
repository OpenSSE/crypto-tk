
#include <assert.h>
#include <unordered_set>
#include "GMPpke.h"
#include "util.h"
#include "prf.hpp"

namespace sse
{

namespace crypto
{

using namespace std;
using namespace relicxx;
//static const string  NULLTAG = "whoever wishes to keep a secret, must hide from us that he possesses one.-- Johann Wolfgang von Goethe"; // the reserved tag

    const tag_type Gmppke::NULLTAG = {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15}};


std::string tag2string(const tag_type& tag)
{
    return string((const char *)tag.data(),tag.size());
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

void Gmppke::keygen(GmppkePublicKey & pk, GmppkePrivateKey & sk, GmppkeSecretParameters &sp) const
{
    GmppkePublicKey bpk;
    const ZR alpha = group.randomZR();
    bpk.gG1 = group.generatorG1();
    bpk.gG2 = group.generatorG2();
    const ZR beta = group.randomZR();
    bpk.g2G1 = group.exp(bpk.gG1, beta);
    bpk.g2G2 = group.exp(bpk.gG2, beta);
    pk.gG1 = bpk.gG1;
    pk.gG2 = bpk.gG2;
    pk.g2G1 = bpk.g2G1;
    pk.g2G2 = bpk.g2G2;
    
    
    sp.alpha = alpha;
    sp.beta = beta;
    sp.ry = group.randomZR();
    
    keygenPartial(alpha,pk,sk, sp);
}

void Gmppke::keygen(const std::array<uint8_t, kPRFKeySize> &prf_key, GmppkePublicKey & pk, GmppkePrivateKey & sk, GmppkeSecretParameters &sp) const
{
    sse::crypto::Prf<kPPKEPrfOutputSize> prf(prf_key.data(), prf_key.size());
    keygen(prf, pk, sk, sp);
}

void Gmppke::keygen(const sse::crypto::Prf<kPPKEPrfOutputSize> &prf, GmppkePublicKey & pk, GmppkePrivateKey & sk, GmppkeSecretParameters &sp) const
{
    paramgen(prf, sp);
    
    GmppkePublicKey bpk;
    //    const ZR alpha = group.randomZR();
    
    const ZR alpha = group.pseudoRandomZR(prf, "param_alpha");
    
    bpk.gG1 = group.generatorG1();
    bpk.gG2 = group.generatorG2();
    //    const ZR beta = group.randomZR();
    const ZR beta = group.pseudoRandomZR(prf, "param_beta");
    bpk.g2G1 = group.exp(bpk.gG1, beta);
    bpk.g2G2 = group.exp(bpk.gG2, beta);
    pk.gG1 = bpk.gG1;
    pk.gG2 = bpk.gG2;
    pk.g2G1 = bpk.g2G1;
    pk.g2G2 = bpk.g2G2;
    
    
    keygenPartial(prf, alpha, pk, sk, sp);
}

void Gmppke::paramgen(const sse::crypto::Prf<kPPKEPrfOutputSize> &prf, GmppkeSecretParameters &sp) const
{
    sp.alpha = group.pseudoRandomZR(prf, "param_alpha");
    sp.beta = group.pseudoRandomZR(prf, "param_beta");
    sp.ry = group.pseudoRandomZR(prf, "param_ry");
}


void Gmppke::keygenPartial(const ZR & alpha, GmppkePublicKey & pk, GmppkePrivateKey & sk, const GmppkeSecretParameters &sp) const
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
    
    
    polynomial_xcordinates[1] = ZR(1);
    pk.gqofxG1[1] = group.mul(group.exp(pk.gG1,sp.ry), pk.g2G1);
    pk.gqofxG2[1] = group.mul(group.exp(pk.gG2,sp.ry), pk.g2G2);
    
    assert(polynomial_xcordinates.size()==pk.gqofxG1.size());
    
    // Sanity check that Lagrange interpolation works to get us g^beta on q(0).
    //    assert(pk.g2G1 == LagrangeInterpInExponent<G1>(group,0,polynomial_xcordinates,pk.gqofxG1));
    //    assert(pk.g2G2 == LagrangeInterpInExponent<G2>(group,0,polynomial_xcordinates,pk.gqofxG2));
    
    
    sk.shares.push_back(skgen(sp));
    
    
    return;
}

void Gmppke::keygenPartial(const sse::crypto::Prf<kPPKEPrfOutputSize> &prf, const ZR & alpha, GmppkePublicKey & pk, GmppkePrivateKey & sk, const GmppkeSecretParameters &sp) const
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
    
    
    //    const ZR ry = group.randomZR();
    
    polynomial_xcordinates[1] = ZR(1);
    pk.gqofxG1[1] = group.mul(group.exp(pk.gG1,sp.ry), pk.g2G1);
    pk.gqofxG2[1] = group.mul(group.exp(pk.gG2,sp.ry), pk.g2G2);
    
    assert(polynomial_xcordinates.size()==pk.gqofxG1.size());
    
    // Sanity check that Lagrange interpolation works to get us g^beta on q(0).
    //    assert(pk.g2G1 == LagrangeInterpInExponent<G1>(group,0,polynomial_xcordinates,pk.gqofxG1));
    //    assert(pk.g2G2 == LagrangeInterpInExponent<G2>(group,0,polynomial_xcordinates,pk.gqofxG2));
    
    sk.shares.push_back(skgen(prf, sp));
    
    
    return;
}

GmppkePrivateKeyShare Gmppke::skgen(const GmppkeSecretParameters &sp ) const{
    GmppkePrivateKeyShare share;
    share.sk4 = NULLTAG;
    const ZR r = group.randomZR();
    //    share.sk1 = group.exp(pk.g2G2, group.add(r,alpha));
    share.sk1 = group.exp(group.generatorG2(), sp.beta*(r+sp.alpha));
    
    const ZR h = group.hashListToZR(NULLTAG);
    
    share.sk3 = group.exp(group.generatorG2(), r); // g^r
    share.sk2 = group.exp(share.sk3, sp.beta + (h* sp.ry));// v(t0)^r
    
    return share;
}

GmppkePrivateKeyShare Gmppke::skgen(const sse::crypto::Prf<kPPKEPrfOutputSize> &prf, const GmppkeSecretParameters &sp  ) const{
    GmppkePrivateKeyShare share;
    share.sk4 = NULLTAG;
    //    const ZR r = group.randomZR();
    const ZR r = group.pseudoRandomZR(prf, "param_r");
    //    share.sk1 = group.exp(pk.g2G2, group.add(r,alpha));
    share.sk1 = group.exp(group.generatorG2(), sp.beta*(r+sp.alpha));
    
    const ZR h = group.hashListToZR(NULLTAG);
    
    share.sk3 = group.exp(group.generatorG2(), r); // g^r
    share.sk2 = group.exp(share.sk3, sp.beta + (h* sp.ry));// v(t0)^r
    
    return share;
}

GmppkePrivateKeyShare Gmppke::sk0Gen(const sse::crypto::Prf<kPPKEPrfOutputSize> &prf, const GmppkeSecretParameters &sp, size_t d) const{
    
    const ZR h = group.hashListToZR(NULLTAG);
    GmppkePrivateKeyShare sk_0;
    
    std::string d_string = std::to_string(d);
    
    //    assert(d > 0);
    if (d == 0) {
        // this is the initial first key share, we have to act a bit differently
        
        const ZR r = group.pseudoRandomZR(prf, "param_rho_0");
        sk_0.sk1 = group.exp(group.generatorG2(), sp.beta*(r+sp.alpha));
        
        sk_0.sk3 = group.exp(group.generatorG2(), r); // g^r
        sk_0.sk2 = group.exp(sk_0.sk3, sp.beta + (h* sp.ry));// v(t0)^r
        
        
    }else{
        const ZR rho_d = group.pseudoRandomZR(prf, ("param_rho_"+ d_string));
        //        std::cout << std::string("param_rho_%d",d) << std::endl;
        //        const ZR rho_d_1 = group.pseudoRandomZR(prf, std::string("param_rho_%d",d-1));
        
        const ZR l_d = group.pseudoRandomZR(prf, ("param_l_" + d_string));
        
        //        const ZR l_d_1 = (d > 1) ? (group.pseudoRandomZR(prf, std::string("param_l_%d",d-1))) : (-sp.alpha);
        
        sk_0.sk1 = group.exp(group.generatorG2(), sp.beta*(rho_d - l_d));
        sk_0.sk3 = group.exp(group.generatorG2(), rho_d); // g^r
        sk_0.sk2 = group.exp(sk_0.sk3, sp.beta + (h* sp.ry));// v(t0)^r
        
    }
    
    sk_0.sk4 = NULLTAG;
    return sk_0;
}

GmppkePrivateKeyShare Gmppke::skShareGen(const sse::crypto::Prf<kPPKEPrfOutputSize> &prf, const GmppkeSecretParameters &sp, size_t d, const tag_type& tag) const{
    
    const ZR h = group.hashListToZR(tag);
    GmppkePrivateKeyShare share;
    
    assert(d > 0);
    assert(tag != NULLTAG);
    std::string d_string = std::to_string(d);
    
    const ZR r1 = group.pseudoRandomZR(prf, ("param_r1_%d" + d_string));
    //        const ZR rho_d_1 = group.pseudoRandomZR(prf, std::string("param_rho_%d",d-1));
    
    const ZR l_d = group.pseudoRandomZR(prf, ("param_l_" + d_string));
    const ZR l_d_1 = (d > 1) ? (group.pseudoRandomZR(prf, std::string("param_l_" + to_string(d-1)))) : (-sp.alpha);
    
    share.sk1 = group.exp(group.generatorG2(), sp.beta*(l_d - l_d_1 + r1));
    share.sk3 = group.exp(group.generatorG2(), r1); // g^r
    share.sk2 = group.exp(share.sk3, sp.beta + (h* sp.ry));// v(t0)^r
    
    
    share.sk4 = tag;
    return share;
}


void Gmppke::puncture(const GmppkePublicKey & pk, GmppkePrivateKey & sk, const tag_type & tag) const{
    
    if(tag == NULLTAG){
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
    if(tag == NULLTAG){
        throw invalid_argument("Invalid tag: the NULLTAG is reserved and cannot be used.");
    }

    PartialGmmppkeCT  ct;
    ct.ct2 = group.exp(pk.gG1, s);
    G1 vofx = vx(pk.gqofxG1,tag);
    ct.ct3 = group.exp(vofx, s);
    
    ct.tag = tag;
    return ct;
}

PartialGmmppkeCT Gmppke::blind(const GmppkeSecretParameters & sp, const relicxx::ZR & s,  const tag_type & tag) const
{
    if(tag == NULLTAG){
        throw invalid_argument("Invalid tag: the NULLTAG is reserved and cannot be used.");
    }

    PartialGmmppkeCT  ct;
    ct.ct2 = group.exp(group.generatorG1(), s);
    
    ZR h = group.hashListToZR(tag);
    G1 g = group.generatorG1();
    
    ct.ct3 = group.exp(ct.ct2, (sp.beta + (h* sp.ry)));
    
    ct.tag = tag;
    return ct;
}


GT Gmppke::recoverBlind(const GmppkePrivateKey & sk, const PartialGmmppkeCT & ct) const
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
        
        
        ZR w0 = LagrangeBasisCoefficients<2>(group,0,0, {{ctTag, currentTag}});
        const ZR wstar = LagrangeBasisCoefficients<2>(group,1,0,{{ctTag, currentTag}});
        
        
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
}
