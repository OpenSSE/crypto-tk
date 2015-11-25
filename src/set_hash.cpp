#include "set_hash.hpp"

#include "ecmh/binary_elliptic_curve/GLS254.hpp"
#include "ecmh/multiset_hash/ECMH.hpp"
#include "ecmh/hash/blake2b.hpp"
#include "ecmh/array_view/array_view.hpp"

using namespace jbms::multiset_hash;

namespace sse
{

namespace crypto
{


class SetHash::SetHashImpl
{
public:

	SetHashImpl();	
	SetHashImpl(const std::string &hex);
	~SetHashImpl();

	void add_element(const std::string &in);
	void remove_element(const std::string &in);
	
	std::string hex() const;
		
private:	
	typedef jbms::multiset_hash::ECMH<jbms::binary_elliptic_curve::GLS254, jbms::hash::blake2b, false> MSH;
    static const MSH ecmh_;
   	MSH::State state_;
};

SetHash::SetHashImpl::MSH const SetHash::SetHashImpl::ecmh_{};

SetHash::SetHash() : set_hash_imp_(new SetHashImpl())
{
}

SetHash::SetHash(const std::string &hex) :  set_hash_imp_(new SetHashImpl(hex))
{
}

SetHash::~SetHash() 
{ 
	delete set_hash_imp_;
}

void SetHash::add_element(const std::string &in)
{
	set_hash_imp_->add_element(in);
}
void SetHash::remove_element(const std::string &in)
{
	set_hash_imp_->remove_element(in);
}

std::string SetHash::hex() const
{
	return set_hash_imp_->hex();
}


std::ostream& operator<<(std::ostream& os, const SetHash& h)
{
	os << h.set_hash_imp_->hex();
	return os;
}

/*
 * SetHashImpl
 *
 */


SetHash::SetHashImpl::SetHashImpl()
{
	state_ = initial_state(ecmh_);
}

SetHash::SetHashImpl::SetHashImpl(const std::string &hex)
{
	state_ = from_hex(ecmh_, hex);
}

SetHash::SetHashImpl::~SetHashImpl() 
{ 
}

void SetHash::SetHashImpl::add_element(const std::string &in)
{
    add(ecmh_, state_, in);
}
void SetHash::SetHashImpl::remove_element(const std::string &in)
{
    remove(ecmh_, state_, in);
}

std::string SetHash::SetHashImpl::hex() const
{
	return to_hex(ecmh_, state_);
}

}
}