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

#include "../src/prf.hpp"
#include "../src/random.hpp"


#include <iostream>
#include <iomanip>
#include <string>

#include "gtest/gtest.h"

#ifdef CHECK_TEMPLATE_INSTANTIATION
/* To avoid file duplication in GCov */
extern template class sse::crypto::Key<1>;
extern template class sse::crypto::Key<10>;
extern template class sse::crypto::Key<20>;
extern template class sse::crypto::Key<128>;
extern template class sse::crypto::Key<1024>;
#endif

using namespace std;
namespace tests {

template <size_t N>
void test_prf_consistency(size_t input_size)
{
    sse::crypto::Prf<N> prf;
    
    string in_s = sse::crypto::random_string(input_size);
    
    ASSERT_EQ(prf.prf(in_s), prf.prf(reinterpret_cast<const uint8_t*>(in_s.data()), input_size));
}
    
template <size_t N> void test_key_derivation_consistency(size_t input_size);
    
template <size_t N>
void test_key_derivation_consistency(size_t input_size)
{
    sse::crypto::Prf<N> prf;
    
    string in_s = sse::crypto::random_string(input_size);
    
    auto out_array = prf.prf(in_s);
    auto out_key = prf.derive_key(in_s);
    out_key.unlock();
    ASSERT_TRUE(memcmp(out_array.data(), out_key.data(), N) == 0);
    out_key.lock();
}

}

TEST(prf, consistency) {
    for (size_t i = 1; i <= 100; i++) {
        tests::test_prf_consistency<1>(i);
        tests::test_prf_consistency<10>(i);
        tests::test_prf_consistency<20>(i);
        tests::test_prf_consistency<128>(i);
        tests::test_prf_consistency<1024>(i);
    }
}

TEST(prf, key_derivation_consistency) {
    for (size_t i = 1; i <= 100; i++) {
        tests::test_key_derivation_consistency<1>(i);
        tests::test_key_derivation_consistency<10>(i);
        tests::test_key_derivation_consistency<20>(i);
        tests::test_key_derivation_consistency<128>(i);
        tests::test_key_derivation_consistency<1024>(i);
    }
}

