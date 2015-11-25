#pragma once

#include <string>

namespace sse
{

namespace crypto
{

/*****
* SetHash class
*
* Opaque class for set hashing.
* 	
* For now, SetHash implements the ECMH function (by Maitin-Shepard, Tibouchi and Aranha)
******/

class SetHash
{
public:

	SetHash();	
	SetHash(const std::string &hex);	
	~SetHash();

	void add_element(const std::string &in);
	void remove_element(const std::string &in);
	
	std::string hex() const;
	
	friend std::ostream& operator<<(std::ostream& os, const SetHash& h);

private:	
	class SetHashImpl; // not defined in the header
	SetHashImpl *set_hash_imp_; // opaque pointer
};

}
}