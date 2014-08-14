#include "config.h"
#include <string.h>
#include <pcap.h>

const char kMainSec[] = "main";

const char kAdapterKey[] = "adapter";
const char kPortKey[] = "tcp_port";
const char kFilterKey[] = "filter";
const char kFilterWordsKey[] = "filter_words";
const char kFilterIdURLKey[] = "filter_idurl";
const char kCheckUpdateKey[] = "auto_check_updates";

const char kDefAdapter[] = "";
const u_int16_t kDefPort = 80;
const bool kDefFilter = true;
const char kDefFilterWords[] = ".mid|.wav|.mp3|.wma|.ra|.avi|.asf|.mkv|.mpg|.ogg|.3gp|.3g2|.m4a|.m4v|.mov|.mpg|.mp4|.rm|.rmvb|.wmv|.flv|.f4v|.f4p|.f4a|.f4b|.ogv|.webm|/videoplayback|.pdf|.rar|.zip|.gz|.bz2|";
const bool kDefFilterIdURL = false;
const bool kDefCheckUpdate = true;


static bool TestAdapterName( const char adapter[] )
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i;
	bool succ = false;

	if( pcap_findalldevs( &alldevs, errbuf ) < 0 )
		{
		return false;
		}//end if

	for( i = 0, d = alldevs; d != NULL; d = d->next, ++i )
		{
		if( strcmp( d->name, adapter ) == 0 )
			{
			succ = true;
			break;
			}//end if
		}//end for

	pcap_freealldevs(alldevs);

	return succ;
}//end TestAdapterName

#ifdef OS_IS_LINUX
#include <glib.h>

void GetConfigFilePath( const char file[], char path[MAX_PATH] )
{
	strcpy( path, "/etc/" );
	strcat( path, file );
}//end GetConfigFilePath

bool LoadConfig( const char file[], Config *cfg )
{
	GKeyFile *keyfile;
	GError *err;
	FILE* fp;
	gchar *str;
	gsize len;
	bool succ;
	bool refill;
	bool modify;

	succ = true;

	keyfile = g_key_file_new();
	g_key_file_load_from_file( keyfile, file,
		static_cast<GKeyFileFlags>(G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS), NULL );

	modify = false;

	refill = true;
	str = g_key_file_get_value( keyfile, kMainSec, kAdapterKey, NULL );
	if( str != NULL )
		{
		if( str[0] != '\0' && TestAdapterName( str ) )
			{
			strncpy( cfg->adapter, str, MAX_ADAPTER_NAME );
			cfg->adapter[MAX_ADAPTER_NAME-1] = '\0';
			refill = false;
			}//end if
		g_free( str );
		}//end if
	if( refill )
		{
		succ = false;
		strcpy( cfg->adapter, kDefAdapter );
		g_key_file_set_value( keyfile, kMainSec, kAdapterKey, kDefAdapter );
		modify = true;
		}//end if

	err = NULL;
	cfg->dst_port = g_key_file_get_integer( keyfile, kMainSec, kPortKey, &err );
	if( err != NULL )
		{
		succ = false;
		cfg->dst_port = kDefPort;
		g_key_file_set_integer( keyfile, kMainSec, kPortKey, kDefPort );
		modify = true;
		}//end if

	err = NULL;
	cfg->filter = g_key_file_get_integer( keyfile, kMainSec, kFilterKey, &err );
	if( err != NULL )
		{
		succ = false;
		cfg->filter = kDefFilter;
		g_key_file_set_integer( keyfile, kMainSec, kFilterKey, kDefFilter );
		modify = true;
		}//end if

	refill = true;
	str = g_key_file_get_value( keyfile, kMainSec, kFilterWordsKey, NULL );
	if( str != NULL )
		{
		strncpy( cfg->filterwords, str, MAX_FILTERWORDS_LEN );
		cfg->filterwords[MAX_FILTERWORDS_LEN-1] = '\0';
		refill = false;
		g_free( str );
		}//end if
	if( refill )
		{
		succ = false;
		strcpy( cfg->filterwords, kDefFilterWords );
		g_key_file_set_value( keyfile, kMainSec, kFilterWordsKey, kDefFilterWords );
		modify = true;
		}//end if

	err = NULL;
	cfg->filteridurl = g_key_file_get_integer( keyfile, kMainSec, kFilterIdURLKey, &err );
	if( err != NULL )
		{
		succ = false;
		cfg->filteridurl = kDefFilterIdURL;
		g_key_file_set_integer( keyfile, kMainSec, kFilterIdURLKey, kDefFilterIdURL );
		modify = true;
		}//end if

	err = NULL;
	cfg->checkupdate = g_key_file_get_integer( keyfile, kMainSec, kCheckUpdateKey, &err );
	if( err != NULL )
		{
		succ = false;
		cfg->checkupdate = kDefCheckUpdate;
		g_key_file_set_integer( keyfile, kMainSec, kCheckUpdateKey, kDefCheckUpdate );
		modify = true;
		}//end if

	if( modify )
		{
		str = g_key_file_to_data( keyfile, &len, NULL );
		fp = fopen( file, "w" );
		if( fp != NULL )
			{
			fwrite( str, len, 1, fp );
			fclose( fp );
			}//end if
		g_free( str );
		}//end if

	g_key_file_free( keyfile );

	return succ;
}//end LoadConfig

bool SaveConfig( const char file[], const Config *cfg )
{
	FILE* fp;
	GKeyFile *keyfile;
	gchar *str;
	gsize len;
	bool succ;

	succ = false;

	keyfile = g_key_file_new();

	g_key_file_set_value( keyfile, kMainSec, kAdapterKey, cfg->adapter );
	g_key_file_set_integer( keyfile, kMainSec, kPortKey, cfg->dst_port );

	g_key_file_set_integer( keyfile, kMainSec, kFilterKey, cfg->filter );
	g_key_file_set_value( keyfile, kMainSec, kFilterWordsKey, cfg->filterwords );

	g_key_file_set_integer( keyfile, kMainSec, kFilterIdURLKey, cfg->filteridurl );
	g_key_file_set_integer( keyfile, kMainSec, kCheckUpdateKey, cfg->checkupdate );

	str = g_key_file_to_data( keyfile, &len, NULL );
	fp = fopen( file, "w" );
	if( fp != NULL )
		{
		fwrite( str, len, 1, fp );
		succ = true;
		fclose( fp );
		}//end if
	g_free( str );

	g_key_file_free( keyfile );
	return succ;
}//end SaveConfig

#else // WINDOWS

void GetConfigFilePath( const char file[], char path[MAX_PATH] )
{
	GetModuleFileNameA( NULL, path, MAX_PATH );
	strcpy( PathFindFileNameA( path ), file );
}//end GetConfigFilePath

bool LoadConfig( const char file[], Config *cfg )
{
	bool succ = true;

	if( GetPrivateProfileStringA( kMainSec, kAdapterKey, kDefAdapter, cfg->adapter, sizeof( cfg->adapter ), file ) == 0
		|| !TestAdapterName( cfg->adapter ) )
		{
		cfg->adapter[0] = '\0';
		succ = false;
		}//end if
	cfg->dst_port = GetPrivateProfileIntA( kMainSec, kPortKey, kDefPort, file );
	cfg->filter = GetPrivateProfileIntA( kMainSec, kFilterKey, kDefFilter, file );
	GetPrivateProfileStringA( kMainSec, kFilterWordsKey, kDefFilterWords, cfg->filterwords, sizeof( cfg->filterwords ), file );
	cfg->filteridurl = GetPrivateProfileIntA( kMainSec, kFilterIdURLKey, kDefFilterIdURL, file );
	cfg->checkupdate = GetPrivateProfileIntA( kMainSec, kCheckUpdateKey, kDefCheckUpdate, file );

	return succ;
}//end LoadConfig

bool SaveConfig( const char file[], const Config *cfg )
{
	char buff[8];
	bool succ;

	succ = WritePrivateProfileStringA( kMainSec, kAdapterKey, cfg->adapter, file );
	succ = WritePrivateProfileStringA( kMainSec, kPortKey, itoa( cfg->dst_port, buff, 10 ), file ) && succ;
	succ = WritePrivateProfileStringA( kMainSec, kFilterKey, itoa( cfg->filter, buff, 10 ), file ) && succ;
	succ = WritePrivateProfileStringA( kMainSec, kFilterWordsKey, cfg->filterwords, file ) && succ;
	succ = WritePrivateProfileStringA( kMainSec, kFilterIdURLKey, itoa( cfg->filteridurl, buff, 10 ), file ) && succ;
	succ = WritePrivateProfileStringA( kMainSec, kCheckUpdateKey, itoa( cfg->checkupdate, buff, 10 ), file ) && succ;

	return succ;
}//end SaveConfig

#endif // OS
