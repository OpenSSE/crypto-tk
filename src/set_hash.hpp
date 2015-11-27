#pragma once

#include <string>
#include <vector>

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
	SetHash(const SetHash& o);
	SetHash(const SetHash&& o);
	SetHash(const std::vector<std::string> &in_set);
	~SetHash();

	void add_element(const std::string &in);
	void add_set(const SetHash &h);
	void remove_element(const std::string &in);
	void remove_set(const SetHash &h);
	SetHash invert_set();
	
	std::string hex() const;
	
	friend std::ostream& operator<<(std::ostream& os, const SetHash& h);
	SetHash& operator=(const SetHash& h);
	bool operator==(const SetHash& h) const;
	bool operator!=(const SetHash& h) const;
private:	
	class SetHashImpl; // not defined in the header
	SetHashImpl *set_hash_imp_; // opaque pointer
};

}
}