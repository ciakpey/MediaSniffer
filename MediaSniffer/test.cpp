#include "MediaSniffer.h"


void Record( void* arg, const SniffRec* rec )
{
	printf( "%s | %s\n", rec->url.c_str(), rec->ua.c_str() );
}//end Record

int main(void)
{
	char config_file[MAX_PATH];
	MediaSniffer ms;
	Config cfg;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_addr_t *a;
	int inum;
	int i;

	GetConfigFilePath( "mediasniffer.ini", config_file );
	if( !LoadConfig( config_file, &cfg ) )
		{
		if( pcap_findalldevs( &alldevs, errbuf ) == -1 )
			{
			printf( "Error in pcap_findalldevs: %s\n", errbuf );
			return -1;
			}//end if

		// show adapter list
		for( i = 0, d = alldevs; d != NULL; d = d->next, ++i )
			{
			for( a = d->addresses; a != NULL; a = a->next )
				{
				if( a->addr->sa_family == AF_INET )
					{
					break;
					}//end if
				}//end for
			printf( "%d. %s %s\n\t", i + 1,
				(a != NULL) ? inet_ntoa( reinterpret_cast<struct sockaddr_in*>(a->addr)->sin_addr ) : "N/A",
				d->name );
			if( d->description != NULL )
				{
				printf( "(%s)\n", d->description );
				}
			else{
				puts( "(No description available)" );
				}//end if
			}//end for
		
		if( i == 0 )
			{
			printf(
#ifdef OS_IS_LINUX
				"Be sure to run as root!\n"
#else // Windows
				"No interfaces found! Make sure WinPcap is installed.\n"
#endif
				);
			return -1;
			}//end if

		// let the user choose an adapter
		printf( "Enter the interface number (1 ~ %d): ", i );
		scanf( "%d", &inum );
		getchar();
		
		if( inum < 1 || inum > i )
			{
			printf("\nInterface number out of range.\n");
			/* Free the device list */
			pcap_freealldevs( alldevs );
			return -1;
			}//end if

		// jump to it
		for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

		strcpy( cfg.adapter, d->name );
		SaveConfig( config_file, &cfg );
		}//end if

	ms.set_show_rec( Record, NULL );

	if( ms.StartSniff( cfg.adapter, cfg.dst_port, cfg.filterwords, cfg.filteridurl ) )
		{
		puts( "Sniff start. Press ENTER to exit" );
		getchar();
		ms.StopSniff();
		}
	else{
		puts( "Failed to start sniff!" );
		}//end if

	return 0;
}//end main
