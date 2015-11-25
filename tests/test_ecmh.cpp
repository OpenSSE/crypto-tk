#include "ecmh/binary_elliptic_curve/GLS254.hpp"
#include "ecmh/multiset_hash/ECMH.hpp"
#include "ecmh/hash/blake2b.hpp"

#include <boost/test/unit_test.hpp>

template <size_t N, class MSH>
void test_generic_multiset_hash_with_size(MSH const &msh) {

  for (int i = 0; i < 100; ++i) {
    size_t num_examples = 3;
    std::vector<std::array<uint8_t, N>> examples(num_examples);
    for (auto &e : examples)
      jbms::openssl::rand_pseudo_bytes(e);

    using State = typename MSH::State;

    State I = initial_state(msh);

#define REQUIRE_HEX_EQUAL(a, b) BOOST_REQUIRE_EQUAL(to_hex(msh, a), to_hex(msh, b))

    // Hex
    {
      State a = I;
      BOOST_REQUIRE(equal(msh, a, from_hex(msh, to_hex(msh, a))));
      REQUIRE_HEX_EQUAL(a, from_hex(msh, to_hex(msh, a)));

      add(msh, a, examples[0]);
      add(msh, a, examples[1]);
      remove(msh, a, examples[2]);
      BOOST_REQUIRE(equal(msh, a, from_hex(msh, to_hex(msh, a))));
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
      BOOST_REQUIRE(equal(msh, a, b));
      BOOST_REQUIRE(equal(msh, b, a));
      BOOST_REQUIRE(!equal(msh, b, I));
      BOOST_REQUIRE(!equal(msh, I, a));
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
      BOOST_REQUIRE(equal(msh, a, c));
      BOOST_REQUIRE(equal(msh, c, a));
    }

    // Inverse property
    {
      State a = I;
      add(msh, a, examples[0]);
      add(msh, a, examples[1]);

      BOOST_REQUIRE(to_hex(msh, a) != to_hex(msh, I));
      BOOST_REQUIRE(!equal(msh, a, I));

      State b = invert(msh, a);

      add_hash(msh, b, a);
      REQUIRE_HEX_EQUAL(b, I);
      BOOST_REQUIRE(equal(msh, b, I));

      State c = a;
      remove(msh, c, examples[0]);
      remove(msh, c, examples[1]);
      REQUIRE_HEX_EQUAL(c, I);
      BOOST_REQUIRE(equal(msh, c, I));
    }

    // Identity
    {
      State a = I;
      add(msh, a, examples[0]);
      add(msh, a, examples[1]);

      State b = a;
      add_hash(msh, b, I);
      REQUIRE_HEX_EQUAL(a, b);
      BOOST_REQUIRE(equal(msh, a, b));

      State c = a;
      remove_hash(msh, c, I);
      REQUIRE_HEX_EQUAL(a, c);
      BOOST_REQUIRE(equal(msh, a, c));
    }

    // Batch add
    {
      State a = I;
      batch_add(msh, a, examples);
      State b = I;
      for (auto &&e : examples)
        add(msh, b, e);
      REQUIRE_HEX_EQUAL(a, b);
      BOOST_REQUIRE(equal(msh, a, b));
    }

    // Batch remove
    {
      State a = I;
      batch_remove(msh, a, examples);
      State b = I;
      for (auto &&e : examples)
        remove(msh, b, e);
      REQUIRE_HEX_EQUAL(a, b);
      BOOST_REQUIRE(equal(msh, a, b));
    }

  }
}

void test_generic_multiset_hash() {
    jbms::multiset_hash::ECMH<jbms::binary_elliptic_curve::GLS254, jbms::hash::blake2b, false> ecmh;
  
    test_generic_multiset_hash_with_size<10>(ecmh);
    test_generic_multiset_hash_with_size<100>(ecmh);
    test_generic_multiset_hash_with_size<150>(ecmh);
}