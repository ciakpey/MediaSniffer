#ifndef CTQY_MEDIASNIFFER_H
#define CTQY_MEDIASNIFFER_H

#include "config.h"
#include "platform.h"
#include "Hash.h"
#include <pcap.h>
#include <vector>

using namespace std;

typedef struct
{
	string url;
	string ua;
} SniffRec;

typedef void (*ShowRec)( void* arg, const SniffRec* rec );

class MediaSniffer
{
public:
	MediaSniffer(void);
	void set_show_rec( ShowRec show_rec, void* arg );
	bool StartSniff( const char *adapter, u_int16_t dst_port, const char* filterwords, bool filter_idurl );
	void StopSniff();
	const SniffRec& operator[]( int index ) const;
	int get_record_num(void) const;
	~MediaSniffer();

private:
	static CALL_BACK cap_routine( MediaSniffer* ms );

	char filterwords_[MAX_FILTERWORDS_LEN];
	char *key_[MAX_FILTERWORDS_LEN/3]; // end with NULL

	bool run_;
	pcap_t *caphandle_;
	Thread_h thread_;

	vector<SniffRec> buff_;
	Hash* hash_;

	ShowRec show_rec_;
	void* sr_arg_;
};


#endif // CTQY_MEDIASNIFFER_H
