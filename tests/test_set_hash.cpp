//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2017 Jeremy Maitin-Shepard, Raphael Bost
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

#include "set_hash_elligator.hpp"
#include "hash.hpp"
#include "random.hpp"

#include <iostream>
#include <vector>

#include "gtest/gtest.h"


template <size_t N>
void test_generic_multiset_hash_with_size() {

  for (int i = 0; i < 100; ++i) {
    size_t num_examples = 3;
    std::vector<std::string> examples(num_examples);
    for (auto &e : examples){
        e = sse::crypto::random_string(N);
	}			
  using sse::crypto::SetHash_Elligator;

	const SetHash_Elligator I;


    // Hex
	{
		SetHash_Elligator a = I;
		SetHash_Elligator b(SetHash_Elligator(a.data()));

        ASSERT_EQ(a,b);

		a.add_element(examples[0]);
		a.add_element(examples[1]);
		a.remove_element(examples[2]);

		b = SetHash_Elligator(a.data());

        ASSERT_EQ(a,b);
    }

    // Commutativity
    {
		SetHash_Elligator a = I, b = I;
		a.add_element(examples[0]);
		a.add_element(examples[1]);

		b.add_element(examples[1]);
		b.add_element(examples[0]);

//        REQUIRE_HEX_EQUAL_MH(a, b);
		ASSERT_EQ(a, b);
		ASSERT_EQ(b, a);
		ASSERT_TRUE((b != I));
		ASSERT_TRUE((I != a));
    }

    // Associative
	{
		SetHash_Elligator a = I, b = I, c = I, d = I;
		a.add_element(examples[0]);
		a.add_element(examples[1]);
		b.add_element(examples[2]);

		a.add_set(b);
		
		c.add_element(examples[0]);
		d.add_element(examples[1]);
		d.add_element(examples[2]);
		
		c.add_set(d);

//        REQUIRE_HEX_EQUAL_MH(a, c);
		ASSERT_EQ(a, c);
		ASSERT_EQ(c, a);
	}
  
	// Inverse property
	{
		SetHash_Elligator a = I;
		a.add_element(examples[0]);
		a.add_element(examples[1]);

		ASSERT_TRUE(a.data() != I.data());
		ASSERT_TRUE(a != I);
		
		SetHash_Elligator c = a;
		c.remove_element(examples[0]);
		c.remove_element(examples[1]);
		ASSERT_TRUE(c == I);
	}

    // Identity
    {
		SetHash_Elligator a;
		
		a.add_element(examples[0]);
		a.add_element(examples[1]);

		SetHash_Elligator b = a;
		b.add_set(I);

        ASSERT_TRUE(a == b);

		SetHash_Elligator c = a;
		c.remove_set(I);

        ASSERT_TRUE(a == c);
    }
	
    // Batch add
    {
      SetHash_Elligator a(std::vector<std::string>(examples.begin(),examples.end()));
	  
      SetHash_Elligator b;
      for (auto &&e : examples)
		  b.add_element(e);
	  
      ASSERT_TRUE(a == b);
    }

    // Move operator
    {
      SetHash_Elligator a(std::vector<std::string>(examples.begin(),examples.end()));
      
      SetHash_Elligator b = a;
      SetHash_Elligator c(std::move(a));

      
      ASSERT_TRUE(c == b);
    }

  }
}

TEST(set_hash, 10_bytes)
{
    test_generic_multiset_hash_with_size<10>();
}

TEST(set_hash, 100_bytes)
{
    test_generic_multiset_hash_with_size<100>();
}

TEST(set_hash, 150_bytes)
{
    test_generic_multiset_hash_with_size<150>();
}
