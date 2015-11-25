#include "src/prf.hpp"

#include "ecmh/binary_elliptic_curve/GLS254.hpp"
#include "ecmh/multiset_hash/ECMH.hpp"
#include "ecmh/hash/blake2b.hpp"

#include <iostream>
#include <iomanip>
#include <string>

using namespace std;

typedef sse::crypto::Prf<16> Prf_16;
typedef sse::crypto::Prf<64> Prf_64;

int main( int argc, char* argv[] ) {
	
	cout << "Debug crypto\n";

    jbms::multiset_hash::ECMH<jbms::binary_elliptic_curve::GLS254, jbms::hash::blake2b, false> msh;

	using MSH = typename jbms::multiset_hash::ECMH<jbms::binary_elliptic_curve::GLS254, jbms::hash::blake2b, false>;
    using State = typename MSH::State;

    State I = initial_state(msh);
	
	constexpr size_t N = 100;
	std::array<uint8_t, N>example;
    jbms::openssl::rand_pseudo_bytes(example);
	
    State a = I;
    State b = I;
	string in = "toto";
	jbms::array_view<void const> input(in);
	
    add(msh, a, in);
    add(msh, b, input);
	
	assert(equal(msh, a, b));
	return 0;	
}