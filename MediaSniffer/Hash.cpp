#include "Hash.h"

Hash::Hash( int prime ) : prime_( prime ), hash_( new list<string>[prime] )
{
}//end Hash::Hash

bool Hash::operator[]( const string& key )
{
	int val = ELFhash( key.c_str() );
	list<string>::iterator i;

	if( !hash_[val].empty() )
		{
		for( i = hash_[val].begin(); i != hash_[val].end(); ++i )
			{
			if( *i == key )
				{
				return true;
				}//end if
			}//end for
		}//end if
	hash_[val].push_back( key );

	return false;
}//end Hash::operator[]

int Hash::ELFhash( const char *key )
{
	unsigned long h = 0;
	unsigned long g;

	while( *key != '\0' )
		{
		h = ( h << 4 ) + *key++;
		g = h & 0xF0000000L;
		if( g != 0 )
			{
			h ^= g >> 24;
			}//end if
		h &= ~g;
		}//end while

	return h % prime_;
}//end Hash::ELFhash

Hash::~Hash()
{
	delete [] hash_;
}
