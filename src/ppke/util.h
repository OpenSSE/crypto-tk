#ifndef SRC_UTIL_H_
#define SRC_UTIL_H_
#include <vector>
#include <array>
#include "relic_wrapper/relic_api.h"

namespace sse
{

namespace crypto
{

template <size_t N>
relicxx::ZR LagrangeBasisCoefficients(const relicxx::PairingGroup & group, const unsigned int & j,const relicxx::ZR &x , const std::array<relicxx::ZR, N> & polynomial_xcordinates){
    unsigned int k = N;
    relicxx::ZR prod = 1;
    for(unsigned int  m=0;m<k;m++){
        if(j != m){
            try{
                relicxx::ZR interim = group.div(group.sub(x,polynomial_xcordinates.at(m)),group.sub(polynomial_xcordinates.at(j),polynomial_xcordinates.at(m)));
                prod = group.mul(prod,interim);
            }catch(const relicxx::RelicDividByZero & t){
                throw std::logic_error("LagrangeBasisCoefficient calculation failed. RelicDividByZero"
                                       " Almost certainly a duplicate x-coordinate: ");// FIXME give cordinate
            }
        }
    }
    return prod;
}

relicxx::ZR LagrangeInterp(const relicxx::PairingGroup & group, const relicxx::ZR &x , const std::vector<relicxx::ZR> & polynomial_xcordinates,
                           const std::vector<relicxx::ZR> & polynomial_ycordinates);

template <class type, size_t N> type LagrangeInterpInExponent( const relicxx::PairingGroup & group,const relicxx::ZR &x, const std::array<relicxx::ZR,N> & polynomial_xcordinates,const std::array<type, N> & exp_polynomial_ycordinates){
    type prod;
    for(uint j = 0; j < N;j++){
        relicxx::ZR lagrangeBasisPolyatX = LagrangeBasisCoefficients(group,j,x,polynomial_xcordinates);
        prod =  group.mul(prod,group.exp(exp_polynomial_ycordinates[j],lagrangeBasisPolyatX));
    }
    return prod;
}
}
}
#endif /* SRC_UTIL_H_ */
