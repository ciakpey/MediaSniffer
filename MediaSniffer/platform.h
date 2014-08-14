#ifndef CTQY_PLATFORM_H
#define CTQY_PLATFORM_H

#if defined(WIN32) || defined(WIN64)
#undef OS_IS_LINUX
#else
#define OS_IS_LINUX
#endif


#ifdef OS_IS_LINUX

#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/ppp_defs.h>
#include <linux/if_pppox.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#define MAX_PATH 260

#define CALL_BACK void*

char* itoa( int val, char *buf, int radix );

typedef pthread_t Thread_h;
typedef pthread_mutex_t CRITICAL_SECTION;
typedef CALL_BACK (*ThreadRoutine)( void* arg );

#define INVAL_THREAD 0

#define InitializeCriticalSection(x) pthread_mutex_init( x, NULL )
#define EnterCriticalSection pthread_mutex_lock
#define LeaveCriticalSection pthread_mutex_unlock
#define DeleteCriticalSection pthread_mutex_destroy

#else // Windows

#include <pcap-stdinc.h>
#include <shlwapi.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ETH_P_PPP_SES 0x8864 

#define ETH_ALEN 6

#define PPP_IP   0x21
#define PPP_IPV6 0x57

#pragma pack(push)
#pragma pack(1)
struct ether_header
{
	u_int8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
	u_int8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
	u_int16_t ether_type;				/* packet type ID field	*/
};

struct pppoe_hdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t ver:4;
	u_int8_t type:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t type:4;
	u_int8_t ver:4;
#else
#error "Unknow Endian"
#endif
	u_int8_t code;
	u_int16_t sid;
	u_int16_t length;
};

struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t ihl:4;
	u_int8_t version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t version:4;
	u_int8_t ihl:4;
#else
#error "Unknow Endian"
#endif
	u_int8_t tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t check;
	u_int32_t saddr;
	u_int32_t daddr;
};

struct ip6_hdr
{
	union
	{
	struct ip6_hdrctl
	{
		u_int32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC, 20 bits flow-ID */
		u_int16_t ip6_un1_plen;   /* payload length */
		u_int8_t  ip6_un1_nxt;	/* next header */
		u_int8_t  ip6_un1_hlim;   /* hop limit */
	} ip6_un1;
	u_int8_t ip6_un2_vfc;	   /* 4 bits version, top 4 bits tclass */
	} ip6_ctlun;
	struct in6_addr ip6_src;	  /* source address */
	struct in6_addr ip6_dst;	  /* destination address */
};
#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim

struct tcphdr
{
	u_int16_t source;
	u_int16_t dest;
	u_int32_t seq;
	u_int32_t ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int16_t res1:4;
	u_int16_t doff:4;
	u_int16_t fin:1;
	u_int16_t syn:1;
	u_int16_t rst:1;
	u_int16_t psh:1;
	u_int16_t ack:1;
	u_int16_t urg:1;
	u_int16_t res2:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int16_t doff:4;
	u_int16_t res1:4;
	u_int16_t res2:2;
	u_int16_t urg:1;
	u_int16_t ack:1;
	u_int16_t psh:1;
	u_int16_t rst:1;
	u_int16_t syn:1;
	u_int16_t fin:1;
#else
#error "Unknow Endian"
#endif
	u_int16_t window;
	u_int16_t check;
	u_int16_t urg_ptr;
};
#pragma pack(pop)

#define strncasecmp _strnicmp
#define strcasestr StrStrIA
#define itoa _itoa

#define CALL_BACK DWORD WINAPI

typedef HANDLE Thread_h;
typedef LPTHREAD_START_ROUTINE ThreadRoutine;

#define INVAL_THREAD NULL

#endif // OS


Thread_h ThreadCreate( ThreadRoutine routine, void *arg );
int ThreadWaitForExit( Thread_h handle ); // return 0: success
void ThreadCloseHandle( Thread_h handle );

void MsSleep( int ms );

#endif // CTQY_PLATFORM_H
