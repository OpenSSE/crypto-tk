//
//  key.cpp
//  libsse_crypto
//
//  Created by Raphael Bost on 23/10/2017.
//  Copyright © 2017 VSSE project. All rights reserved.
//

#include "key.hpp"

#include <iostream>

namespace sse {
    namespace crypto {
        template class Key<16>;
        template class Key<32>;

        void test_keys()
        {
            std::cout << "Test keys" << std::endl;
            sse::crypto::Key<32> key;
            key.lock();
        }
        
    }
}
