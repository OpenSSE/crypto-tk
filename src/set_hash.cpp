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
	~SetHashImpl();

	void add_element(const std::string &in);
	void remove_element(const std::string &in);
	
private:	
	typedef jbms::multiset_hash::ECMH<jbms::binary_elliptic_curve::GLS254, jbms::hash::blake2b, false> MSH;
    MSH ecmh_;
   	MSH::State state_;
};

SetHash::SetHash() : set_hash_imp_(new SetHashImpl())
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

SetHash::SetHashImpl::SetHashImpl()
{
	state_ = initial_state(ecmh_);
}

SetHash::SetHashImpl::~SetHashImpl() 
{ 
}

void SetHash::SetHashImpl::add_element(const std::string &in)
{
    // jbms::multiset_hash::add(ecmh_, state_, in);
	jbms::array_view<void const> input;

    add(ecmh_, state_, in);
}
void SetHash::SetHashImpl::remove_element(const std::string &in)
{
	// set_hash_imp_->remove(in);
	jbms::array_view<void const> input;
	
    remove(ecmh_, state_, in);
}

}
}