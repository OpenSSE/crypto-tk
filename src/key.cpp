//
//  key.cpp
//  libsse_crypto
//
//  Created by Raphael Bost on 11/11/2017.
//  Copyright © 2017 VSSE project. All rights reserved.
//

#include "key.hpp"

#include "hash/sha512.hpp"

// Instantiation of some Key templates
namespace sse {
    namespace crypto {
        template class Key<16>;
        template class Key<32>;
        template class Key<48>;
        template class Key<112>;
        template class Key<176>;
        template class Key<244>;

        
#ifdef CHECK_TEMPLATE_INSTANTIATION
#pragma message "Instantiate templates for unit tests and code coverage"
        /* To avoid file duplication in GCov */
        
        template class Key<1>;
        template class Key<10>;
        template class Key<18>;
        template class Key<20>;
        template class Key<25>;
        template class Key<128>;
        template class Key<1024>;
#endif

    }
}
