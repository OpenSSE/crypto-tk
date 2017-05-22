//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2106 Jeremy Maitin-Shepard, Raphael Bost
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

#include "ecmh/binary_elliptic_curve/GLS254.hpp"
#include "ecmh/multiset_hash/ECMH.hpp"
#include "../src/set_hash.hpp"
#include "hash.hpp"
#include "random.hpp"

#include <iostream>
#include <vector>

#include "gtest/gtest.h"

template <size_t N, class MSH>
void test_ecmh_with_size(MSH const &msh) {

  for (int i = 0; i < 100; ++i) {
    size_t num_examples = 3;
    std::vector<std::array<uint8_t, N>> examples(num_examples);
    for (auto &e : examples)
		sse::crypto::random_bytes(e);

    using State = typename MSH::State;

    State I = initial_state(msh);

#define REQUIRE_HEX_EQUAL(a, b) ASSERT_EQ(to_hex(msh, a), to_hex(msh, b))

    // Hex
    {
      State a = I;
      ASSERT_TRUE(equal(msh, a, from_hex(msh, to_hex(msh, a))));
      REQUIRE_HEX_EQUAL(a, from_hex(msh, to_hex(msh, a)));

      add(msh, a, examples[0]);
      add(msh, a, examples[1]);
      remove(msh, a, examples[2]);
      ASSERT_TRUE(equal(msh, a, from_hex(msh, to_hex(msh, a))));
      REQUIRE_HEX_EQUAL(a, from_hex(msh, to_hex(msh, a)));
    }

    // Commutativity
    {
      State a = I, b = I;
      add(msh, a, examples[0]);
      add(msh, a, examples[1]);

      add(msh, b, examples[1]);
      add(msh, b, examples[0]);

      REQUIRE_HEX_EQUAL(a, b);
      ASSERT_TRUE(equal(msh, a, b));
      ASSERT_TRUE(equal(msh, b, a));
      ASSERT_TRUE(!equal(msh, b, I));
      ASSERT_TRUE(!equal(msh, I, a));
    }

    // Associative
    {
      State a = I, b = I, c = I, d = I;
      add(msh, a, examples[0]);
      add(msh, a, examples[1]);
      add(msh, b, examples[2]);

      add_hash(msh, a, b);

      add(msh, c, examples[0]);
      add(msh, d, examples[1]);
      add(msh, d, examples[2]);

      add_hash(msh, c, d);

      REQUIRE_HEX_EQUAL(a, c);
      ASSERT_TRUE(equal(msh, a, c));
      ASSERT_TRUE(equal(msh, c, a));
    }

    // Inverse property
    {
      State a = I;
      add(msh, a, examples[0]);
      add(msh, a, examples[1]);

      ASSERT_TRUE(to_hex(msh, a) != to_hex(msh, I));
      ASSERT_TRUE(!equal(msh, a, I));

      State b = invert(msh, a);

      add_hash(msh, b, a);
      REQUIRE_HEX_EQUAL(b, I);
      ASSERT_TRUE(equal(msh, b, I));

      State c = a;
      remove(msh, c, examples[0]);
      remove(msh, c, examples[1]);
      REQUIRE_HEX_EQUAL(c, I);
      ASSERT_TRUE(equal(msh, c, I));
    }

    // Identity
    {
      State a = I;
      add(msh, a, examples[0]);
      add(msh, a, examples[1]);

      State b = a;
      add_hash(msh, b, I);
      REQUIRE_HEX_EQUAL(a, b);
      ASSERT_TRUE(equal(msh, a, b));

      State c = a;
      remove_hash(msh, c, I);
      REQUIRE_HEX_EQUAL(a, c);
      ASSERT_TRUE(equal(msh, a, c));
    }

    // Batch add
    {
      State a = I;
      batch_add(msh, a, examples);
      State b = I;
      for (auto &&e : examples)
        add(msh, b, e);
      REQUIRE_HEX_EQUAL(a, b);
      ASSERT_TRUE(equal(msh, a, b));
    }

    // Batch remove
    {
      State a = I;
      batch_remove(msh, a, examples);
      State b = I;
      for (auto &&e : examples)
        remove(msh, b, e);
      REQUIRE_HEX_EQUAL(a, b);
      ASSERT_TRUE(equal(msh, a, b));
    }

  }
}

template <size_t N>
void test_generic_multiset_hash_with_size() {

  for (int i = 0; i < 100; ++i) {
    size_t num_examples = 3;
    // std::vector<std::array<uint8_t, N>> examples(num_examples);
    std::vector<std::string> examples(num_examples);
    for (auto &e : examples){
        e = sse::crypto::random_string(N);
	}			
  using sse::crypto::SetHash;

	const SetHash I;
    // State I = initial_state(msh);

#define REQUIRE_HEX_EQUAL_MH(a, b) ASSERT_EQ(a.hex(), b.hex())

    // Hex
	{
		SetHash a = I;
		SetHash b(SetHash(a.hex()));
		ASSERT_EQ(a,b);
		REQUIRE_HEX_EQUAL_MH(a, b);

		a.add_element(examples[0]);
		a.add_element(examples[1]);
		a.remove_element(examples[2]);

		b = SetHash(a.hex());
		ASSERT_EQ(a,b);
		REQUIRE_HEX_EQUAL_MH(a, b);
    }

    // Commutativity
    {
		SetHash a = I, b = I;
		a.add_element(examples[0]);
		a.add_element(examples[1]);

		b.add_element(examples[1]);
		b.add_element(examples[0]);

		REQUIRE_HEX_EQUAL_MH(a, b);
		ASSERT_EQ(a, b);
		ASSERT_EQ(b, a);
		ASSERT_TRUE((b != I));
		ASSERT_TRUE((I != a));
    }

    // Associative
	{
		SetHash a = I, b = I, c = I, d = I;
		a.add_element(examples[0]);
		a.add_element(examples[1]);
		b.add_element(examples[2]);

		a.add_set(b);
		
		c.add_element(examples[0]);
		d.add_element(examples[1]);
		d.add_element(examples[2]);
		
		c.add_set(d);

		REQUIRE_HEX_EQUAL_MH(a, c);
		ASSERT_EQ(a, c);
		ASSERT_EQ(c, a);
	}
  
	// Inverse property
	{
		SetHash a = I;
		a.add_element(examples[0]);
		a.add_element(examples[1]);

		// BOOST_REQUIRE(to_hex(msh, a) != to_hex(msh, I));
		// BOOST_REQUIRE(!equal(msh, a, I));

		ASSERT_TRUE(a.hex() != I.hex());
		ASSERT_TRUE(a != I);
		
		SetHash b = a.invert_set();
		
		b.add_set(a);
		REQUIRE_HEX_EQUAL_MH(b, I);
		ASSERT_TRUE(b == I);

		SetHash c = a;
		c.remove_element(examples[0]);
		c.remove_element(examples[1]);
		REQUIRE_HEX_EQUAL_MH(c, I);
		ASSERT_TRUE(c == I);
	}

    // Identity
    {
		SetHash a;
		
		a.add_element(examples[0]);
		a.add_element(examples[1]);

		SetHash b = a;
		b.add_set(I);
		REQUIRE_HEX_EQUAL_MH(a, b);
		ASSERT_TRUE(a == b);

		SetHash c = a;
		c.remove_set(I);
		REQUIRE_HEX_EQUAL_MH(a, c);
		ASSERT_TRUE(a == c);
    }
	
    // Batch add
    {
      SetHash a = SetHash(std::vector<std::string>(examples.begin(),examples.end()));
	  
      SetHash b;
      for (auto &&e : examples)
		  b.add_element(e);
	  
      REQUIRE_HEX_EQUAL_MH(a, b);
      ASSERT_TRUE(a == b);
    }
	
  }
}

class TestHash
{
public:
    constexpr static size_t digest_bytes = sse::crypto::Hash::kDigestSize;
    constexpr static size_t block_bytes = sse::crypto::Hash::kBlockSize;
	
    static void hash(unsigned char *out, const unsigned char *in, size_t inlen)
	{
		sse::crypto::Hash::hash(in, inlen, out);
	}
	
};

TEST(set_hash, ecmh_10)
{
    jbms::multiset_hash::ECMH<jbms::binary_elliptic_curve::GLS254,TestHash, false> ecmh;
    test_ecmh_with_size<10>(ecmh);
}

TEST(set_hash, ecmh_100)
{
    jbms::multiset_hash::ECMH<jbms::binary_elliptic_curve::GLS254,TestHash, false> ecmh;
    test_ecmh_with_size<100>(ecmh);
}

TEST(set_hash, ecmh_150)
{
    jbms::multiset_hash::ECMH<jbms::binary_elliptic_curve::GLS254,TestHash, false> ecmh;
    test_ecmh_with_size<150>(ecmh);
}

TEST(set_hash, generic_hash_10)
{
    jbms::multiset_hash::ECMH<jbms::binary_elliptic_curve::GLS254,TestHash, false> ecmh;
    test_generic_multiset_hash_with_size<10>();
}

TEST(set_hash, generic_hash_100)
{
    jbms::multiset_hash::ECMH<jbms::binary_elliptic_curve::GLS254,TestHash, false> ecmh;
    test_generic_multiset_hash_with_size<100>();
}

TEST(set_hash, generic_hash_150)
{
    jbms::multiset_hash::ECMH<jbms::binary_elliptic_curve::GLS254,TestHash, false> ecmh;
    test_generic_multiset_hash_with_size<150>();
}
