#include "MediaSniffer.h"
#include <ctype.h>

#pragma pack(push)
#pragma pack(1) 
typedef struct
{
	struct ether_header eh;
	union
	{
		struct
		{
			struct pppoe_hdr ppph;
			u_int16_t proto;
			union
			{
				struct iphdr iph;
				struct ip6_hdr ip6h;
			};
		} ppp;
		struct iphdr iph;
		struct ip6_hdr ip6h;
	};
} Packet_Hdr;
#pragma pack(pop)

#define LISTEN_TIMESLICE 25

const u_long kGetTag = 0x47455420; // 'GET '

const char kHttpPro[] = "http://";
const int kHttpProLen = (sizeof(kHttpPro) / sizeof(kHttpPro[0])) - 1;

const char kHost[] = "Host: ";
const int kHostLen = (sizeof(kHost) / sizeof(kHost[0])) - 1;

const char kUserAgent[] = "User-Agent: ";
const int kUserAgentLen = (sizeof(kUserAgent) / sizeof(kUserAgent[0])) - 1;


// str end with ' ', lostr end with '\0'
static const char* my_stristr( const char *str, const char *lostr )
{
	const char *cp = str;
	const char *s1, *s2;

	while( *cp != ' ' )
		{
		s1 = cp;
		s2 = lostr;

		while( *s1 != ' ' && *s2 != '\0' && tolower(*s1) == *s2 )
			{
			++s1, ++s2;
			}//end while

		if( *s2 == '\0' && !isalnum( *s1 ) )
			{
			return cp;
			}//end if

		++cp;
		}//end while

	return NULL;
}//end my_stristr

static const char* strnchr( const char *s, int c, int n )
{
	for( ; n > 0; --n )
		{
		if( *s == c )
			{
			return s;
			}
		else{
			++s;
			}//end if
		}//end for

	return NULL;
}//end strnchr

MediaSniffer::MediaSniffer(void) : run_( false ), caphandle_( NULL ), thread_( INVAL_THREAD ), hash_( NULL ),
								   show_rec_( NULL ), sr_arg_( NULL )
{
	filterwords_[0] = filterwords_[1] = '\0';
	key_[0] = NULL;
}//end MediaSniffer::MediaSniffer

void MediaSniffer::set_show_rec( ShowRec show_rec, void* arg )
{
	show_rec_ = show_rec;
	sr_arg_ = arg;
}//end MediaSniffer::set_show_rec

bool MediaSniffer::StartSniff( const char *adapter, u_int16_t dst_port, const char* filterwords, bool filter_idurl )
{
	// tcp dst port = dst_port, http head = 'GET '
	const struct bpf_insn filter[] =
	{
		BPF_STMT(BPF_LD|BPF_H|BPF_ABS, sizeof(u_int8_t[ETH_ALEN])+sizeof(u_int8_t[ETH_ALEN])),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ETH_P_PPP_SES, 0, 4),
		// check for ppp proto
		BPF_STMT(BPF_LDX|BPF_W|BPF_IMM, sizeof(struct pppoe_hdr)+sizeof(u_int16_t)), // X <- ppp header + ppp protocol len
		BPF_STMT(BPF_LD|BPF_H|BPF_IND, sizeof(struct ether_header)-sizeof(u_int16_t)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, PPP_IP, 8, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, PPP_IPV6, 3, 28),
		// check for ip proto
		BPF_STMT(BPF_LDX|BPF_W|BPF_IMM, 0), // X <- 0
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ETH_P_IPV6, 1, 0),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ETH_P_IP, 4, 25),
		// check for ipv6 proto
		BPF_STMT(BPF_LD|BPF_B|BPF_IND, sizeof(struct ether_header)+sizeof(u_int32_t)+sizeof(u_int16_t)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_TCP, 0, 23),
		BPF_STMT(BPF_LD|BPF_IMM, sizeof(struct ip6_hdr)), // A <- ipv6 header len
		BPF_JUMP(BPF_JMP|BPF_JA, 9, 0, 0),
		// check for ipv4 proto
		BPF_STMT(BPF_LD|BPF_B|BPF_IND, sizeof(struct ether_header)+9),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_TCP, 0, 19),
		BPF_STMT(BPF_LD|BPF_H|BPF_IND, 20), // get ip fragment
		BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, 0x1fff, 17, 0),
		BPF_STMT(BPF_MISC|BPF_TXA, 0), // A <- X
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 0, 2), // if X == 0
		BPF_STMT(BPF_LDX|BPF_B|BPF_MSH, sizeof(struct ether_header)), // X <- ipv4 header len (IP)
		BPF_JUMP(BPF_JMP|BPF_JA, 1, 0, 0),
		BPF_STMT(BPF_LDX|BPF_B|BPF_MSH, sizeof(struct ether_header)+sizeof(struct pppoe_hdr)+sizeof(u_int16_t)), // X <- ipv4 header len (PPPoE)
		BPF_STMT(BPF_ALU|BPF_ADD|BPF_X, 0), // A += X
		BPF_STMT(BPF_MISC|BPF_TAX, 0), // X <- A
		// check tcp dest port
		BPF_STMT(BPF_LD|BPF_H|BPF_IND, sizeof(struct ether_header)+sizeof(u_int16_t)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, dst_port, 0, 8),
		// get tcp header len
		BPF_STMT(BPF_LD|BPF_B|BPF_IND, sizeof(struct ether_header)+12), // A <- tcp[12]
		BPF_STMT(BPF_ALU|BPF_AND|BPF_K, 0xf0), // A &= 0xf0
		BPF_STMT(BPF_ALU|BPF_RSH|BPF_K, 2), // A >>= 2 (A now is tcp header len)
		BPF_STMT(BPF_ALU|BPF_ADD|BPF_X, 0), // A += X
		BPF_STMT(BPF_MISC|BPF_TAX, 0), // X <- A
		// check http 'GET '
		BPF_STMT(BPF_LD|BPF_W|BPF_IND, sizeof(struct ether_header)),
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, kGetTag, 0, 1),
		// returns
		BPF_STMT(BPF_RET|BPF_K, 0x0000ffff), // pass
		BPF_STMT(BPF_RET|BPF_K, 0) // reject
	};
	struct bpf_program fcode =
	{
		sizeof(filter)/sizeof(filter[0]),
		const_cast<struct bpf_insn*>(filter)
	};
	char errbuf[PCAP_ERRBUF_SIZE];
	char *p;
	int i;
	bool succ = false;

	if( run_ )
		{
		return true;
		}//end if

	if( filterwords != NULL )
		{
		i = 0;
		do	{
			filterwords_[i] = tolower( filterwords[i] );
			} while( filterwords[i++] != '\0' );
		key_[0] = filterwords_;
		i = 0;
		while( (p = strchr( key_[i], '|' )) != NULL )
			{
			*p = '\0';
			++p;
			++i;
			if( *p == '\0' )
				{
				break;
				}//end if
			key_[i] = p;
			}//end while
		if( p == NULL )
			{
			++i;
			}//end if
		key_[i] = NULL;
		}
	else{
		key_[0] = NULL;
		filterwords_[0] = '\0';
		}//end if

	buff_.clear();
	delete hash_;
	hash_ = NULL;

	caphandle_ = pcap_open_live( adapter, 65535, 0, 1, errbuf );
	if( caphandle_ != NULL )
		{
		run_ = true;
		// apply filter
		if( pcap_setfilter( caphandle_, &fcode ) >= 0 )
			{
			if( filter_idurl )
				{
				hash_ = new Hash( filterwords == NULL ? 2039 : 509 );
				}//end if
			// start the thread
			thread_ = ThreadCreate( reinterpret_cast<ThreadRoutine>(cap_routine), this );
			if( thread_ != INVAL_THREAD )
				{
				succ = true;
				}//end if
			}//end if

		if( !succ )
			{
			StopSniff();
			}//end if
		}//end if

	return succ;
}//end MediaSniffer::StartSniff

void MediaSniffer::StopSniff()
{
	if( run_ )
		{
		run_ = false;

		if( thread_ != INVAL_THREAD )
			{
			// waiting for the thread
			ThreadWaitForExit( thread_ );
			ThreadCloseHandle( thread_ );
			thread_ = INVAL_THREAD;
			}//end if

		if( caphandle_ != NULL )
			{
			pcap_close( caphandle_ );
			caphandle_ = NULL;
			}//end if

		delete hash_;
		hash_ = NULL;
		}//end if
}//end MediaSniffer::StopSniff

const SniffRec& MediaSniffer::operator[]( int index ) const
{
	return buff_[index];
}//end MediaSniffer::operator[]

int MediaSniffer::get_record_num(void) const
{
	return buff_.size();
}//end MediaSniffer::get_record_num

CALL_BACK MediaSniffer::cap_routine( MediaSniffer* ms )
{
	SniffRec rec;
	struct pcap_pkthdr *pkt_header;
	const Packet_Hdr *pkt_data;
	const tcphdr *tcph;
	const char *b, *e, *hb, *he, *pe;
	int ret, len, j;
	bool match;

	pcap_setnonblock( ms->caphandle_, 1, NULL );
	while( ms->run_ )
		{
		ret = pcap_next_ex( ms->caphandle_, &pkt_header, reinterpret_cast<const u_char**>(&pkt_data) );
		if( ret == 1 )
			{
			if( ntohs(pkt_data->eh.ether_type) == ETH_P_PPP_SES )
				{
				if( ntohs(pkt_data->ppp.proto) == PPP_IP )
					{
					tcph = reinterpret_cast<const struct tcphdr*>(reinterpret_cast<const char*>(pkt_data)
							+ sizeof(struct ether_header) + sizeof(struct pppoe_hdr) + sizeof(u_int16_t) + (pkt_data->ppp.iph.ihl << 2));
					}
				else{// IPv6
					tcph = reinterpret_cast<const struct tcphdr*>(reinterpret_cast<const char*>(pkt_data)
							+ sizeof(struct ether_header) + sizeof(struct pppoe_hdr) + sizeof(u_int16_t) + sizeof(struct ip6_hdr));
					}//end if
				}
			else if( ntohs(pkt_data->eh.ether_type) == ETH_P_IPV6 )
				{
				tcph = reinterpret_cast<const struct tcphdr*>(reinterpret_cast<const char*>(pkt_data)
						+ sizeof(struct ether_header) + sizeof(struct ip6_hdr));
				}
			else{// IPv4
				tcph = reinterpret_cast<const struct tcphdr*>(reinterpret_cast<const char*>(pkt_data)
						+ sizeof(struct ether_header) + (pkt_data->iph.ihl << 2));
				}//end if
			pe = reinterpret_cast<const char*>(pkt_data) + pkt_header->caplen;
			b = reinterpret_cast<const char*>(tcph) + (tcph->doff << 2) + sizeof(kGetTag);
			e = strnchr( b, ' ', pe - b );
			if( e == NULL )
				{
				e = pe;
				}//end if

			if( ms->key_[0] != NULL )
				{
				match = false;
				for( j = 0; ms->key_[j] != NULL; ++j )
					{
					if( my_stristr( b, ms->key_[j] ) != NULL )
						{
						match = true;
						break;
						}//end if
					}//end for
				}
			else{// do not filter
				match = true;
				}//end if

			if( match )
				{
				len = e - b;
				if( len > kHttpProLen && strncasecmp( b, kHttpPro, kHttpProLen ) == 0 )
					{
					rec.url = string( b, len );
					}
				else{
					rec.url = string( kHttpPro );
					// find 'Host: '
					hb = e + 1;
					if( hb < pe )
						{
						do	{
							hb = strnchr( hb, '\r', pe - hb );
							if( hb != NULL )
								{
								hb += 2;
								if( hb + kHostLen < pe && strncasecmp( hb, kHost, kHostLen ) == 0 )
									{
									hb += kHostLen;
									he = strnchr( hb, '\r', pe - hb );
									if( he != NULL )
										{
										rec.url.append( hb, he - hb );
										}//end if
									break;
									}//end if
								}//end if
							} while( hb != NULL && *hb != '\r' );
						}//end if
					rec.url.append( b -4, e - b+4 );
					}//end if

				if( ms->hash_ == NULL || !(*ms->hash_)[rec.url] )
					{
					// find 'User-Agent: '
					rec.ua.clear();
					hb = e + 1;
					if( hb < pe )
						{
						do	{
							hb = strnchr( hb, '\r', pe - hb );
							if( hb != NULL )
								{
								hb += 2;
								if( hb + kUserAgentLen < pe && strncasecmp( hb, kUserAgent, kUserAgentLen ) == 0 )
									{
									hb += kUserAgentLen;
									he = strnchr( hb, '\r', pe - hb );
									if( he != NULL )
										{
										rec.ua = string( hb, he - hb );
										}//end if
									break;
									}//end if
								}//end if
							} while( hb != NULL && *hb != '\r' );
						}//end if
					if( rec.ua.empty() )
						{
						rec.ua = "<null>";
						}//end if
					ms->buff_.push_back( rec );
					if( ms->show_rec_ != NULL )
						{
						ms->show_rec_( ms->sr_arg_, &rec );
						}//end if
					}//end if
				}//end if
			}
		else if( ret == 0 )
			{
			// do nothing
			MsSleep( LISTEN_TIMESLICE );
			}
		else{
			break;
			}//end if
		}//end while

	return 0;
}//end MediaSniffer::cap_routine

MediaSniffer::~MediaSniffer()
{
	StopSniff();
}//end MediaSniffer::~MediaSniffer
