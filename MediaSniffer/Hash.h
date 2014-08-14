#ifndef CTQY_HASH_H
#define CTQY_HASH_H

#include <string>
#include <list>

using namespace std;

class Hash
{
public:
	Hash( int prime );
	bool operator[]( const string& key );// return exist
	~Hash();

private:
	Hash(void);
	int ELFhash( const char *key );

	int prime_;
	list<string>* hash_;
};

#endif // CTQY_HASH_H
