#include<assert.h>
#include"util.h"
#include <cmath>
using namespace std;
namespace sse
{

namespace crypto
{

using namespace relicxx;

ZR LagrangeBasisCoefficients(const PairingGroup & group, const unsigned int & j,const ZR &x , const vector<ZR> & polynomial_xcordinates){
    unsigned int k = (unsigned int)polynomial_xcordinates.size();
    ZR prod = 1;
    for(unsigned int  m=0;m<k;m++){
        if(j != m){
            try{
                ZR interim = group.div(group.sub(x,polynomial_xcordinates.at(m)),group.sub(polynomial_xcordinates.at(j),polynomial_xcordinates.at(m)));
                prod = group.mul(prod,interim);
            }catch(const RelicDividByZero & t){
                throw logic_error("LagrangeBasisCoefficient calculation failed. RelicDividByZero"
                                  " Almost certainly a duplicate x-coordinate: ");// FIXME give cordinate
            }
        }
    }
    return prod;
}

ZR LagrangeInterp(const PairingGroup & group, const ZR &x , const vector<ZR> & polynomial_xcordinates,
                  const vector<ZR> & polynomial_ycordinates){
    unsigned int k = (unsigned int)polynomial_ycordinates.size();
    assert(polynomial_xcordinates.size()==polynomial_ycordinates.size());
    ZR prod = 0;
    for(unsigned int j = 0; j < k;j++){
        ZR lagrangeBasisPolyatX = LagrangeBasisCoefficients(group,j,x,polynomial_xcordinates);
        //   cout << "y_ " << j << "= "<<polynomial_ycordinates[j] << " coef = " << lagrangeBasisPolyatX << " prod = " << prod<< endl;
        prod =  group.add(prod,group.mul(lagrangeBasisPolyatX,polynomial_ycordinates.at(j)));
        
    }
    
    // cout << "final prod =" << prod << endl;
    return prod;
}
}
}
