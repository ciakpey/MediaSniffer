#include "update.h"
#include "uicommon.h"
#include "../MediaSniffer/platform.h"
#include <sys/utsname.h>
#include <curl/curl.h>

static const char kUrl[] = "http://mediasniffer.sourceforge.net/v.php?os=linux&q=";
static const char kVer[] = "ver";
static const char kFile[] = "file";
static const char kFolderUrl[] = "http://sf.net/projects/mediasniffer/files/linux-src/";

typedef struct
{
	char *data;
	size_t maxlen;
	size_t len;
} WriteParam;

static bool run = false;

inline size_t min( size_t a, size_t b )
{
	return (a > b) ? b : a;
}//end min

size_t writeproc( void *data, size_t size, size_t nmemb, WriteParam *p )
{
	size_t recvsize = 0;

	if( p->len + 1 < p->maxlen )
		{
		recvsize = min( p->maxlen - p->len - 1, size * nmemb );
		memcpy( p->data + p->len, data, recvsize );
		p->len += recvsize;
		}//end if

	return recvsize;
}//end writeproc

static size_t HttpGetData( const char url[], const struct curl_slist *slist, char data[], size_t len )
{
	WriteParam param = { data, len, 0 };
	CURL *curl;
	
	curl = curl_easy_init();
	if( curl != NULL )
		{
		curl_easy_setopt( curl, CURLOPT_URL, url );
		curl_easy_setopt( curl, CURLOPT_HTTPHEADER, slist );
		curl_easy_setopt( curl, CURLOPT_HEADER, 0 );
		curl_easy_setopt( curl, CURLOPT_FOLLOWLOCATION, 1 );
		curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, writeproc );
		curl_easy_setopt( curl, CURLOPT_WRITEDATA, &param );
		curl_easy_perform( curl );
		curl_easy_cleanup( curl );
		}//end if
	data[param.len] = '\0';
	
	return param.len;
}//end HttpGetData

void* CheckProc( bool silent )
{
	char url[512];
	char buff[260];
	struct utsname un;
	struct curl_slist *slist;
	unsigned int a, b, c, d;
	unsigned long long curver, newver;
	GtkWidget *dlg;
	bool neterr = false;

	run = true;

	slist = NULL;

	strcpy( buff, "User-Agent: Media_Sniffer/" );
	strcat( buff, kVersion );
	if( uname( &un ) == 0 )
		{
		strcat( buff, " " );
		strcat( buff, un.sysname );
		strcat( buff, " " );
		strcat( buff, un.release );
		}
	else{
		strcat( buff, " Linux" );
		}//end if
	slist = curl_slist_append( slist, buff );

	strcpy( buff, "Accept-Language: " );
	strcat( buff, pango_language_to_string( gtk_get_default_language() ) );
	slist = curl_slist_append( slist, buff );
	
	strcpy( url, kUrl );
	strcat( url, kVer );
	if( HttpGetData( url, slist, buff, sizeof(buff) ) > 0
		&& sscanf( buff, "%u.%u.%u.%u", &a, &b, &c, &d ) == 4 )
		{
		newver = (static_cast<unsigned long long>(a) << 48) + (static_cast<unsigned long long>(b) << 32) + (c << 16) + d;
		sscanf( kVersion, "%u.%u.%u.%u", &a, &b, &c, &d );
		curver = (static_cast<unsigned long long>(a) << 48) + (static_cast<unsigned long long>(b) << 32) + (c << 16) + d;
		if( curver < newver )
			{
			strcpy( url, kUrl );
			strcat( url, kFile );
			if( HttpGetData( url, slist, buff, sizeof(buff) ) > 0 )
				{
				strcpy( url, kFolderUrl );
				strcat( url, buff );
				gdk_threads_enter();
				dlg = gtk_message_dialog_new( NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK_CANCEL,
						"There is a new version available:\n\n%s\n\nPress \"OK\" to copy the URL to clipboard.", url );
				if( gtk_dialog_run( GTK_DIALOG(dlg) ) == GTK_RESPONSE_OK )
					{
					gtk_clipboard_set_text( gtk_clipboard_get( GDK_SELECTION_CLIPBOARD ), url, -1 );
					}//end if
				gtk_widget_destroy( dlg );
				gdk_threads_leave();
				}
			else{
				neterr = true;
				}//end if
			}
		else{
			if( !silent )
				{
				gdk_threads_enter();
				dlg = gtk_message_dialog_new( NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_OTHER, GTK_BUTTONS_OK,
						"You already have the latest version!" );
				gtk_dialog_run( GTK_DIALOG(dlg) );
				gtk_widget_destroy( dlg );
				gdk_threads_leave();
				}//end if
			}//end if
		}
	else{
		neterr = true;
		}//end if
	curl_slist_free_all( slist );

	if( neterr && !silent )
		{
		gdk_threads_enter();
		dlg = gtk_message_dialog_new( NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "Failed to get update information!" );
		gtk_dialog_run( GTK_DIALOG(dlg) );
		gtk_widget_destroy( dlg );
		gdk_threads_leave();
		}//end if


	run = false;
	return 0;
}//end CheckProc

void CheckForUpdates( bool silent )
{
	pthread_t handle;
	
	if( !run )
		{
		pthread_create( &handle, NULL, reinterpret_cast<ThreadRoutine>(CheckProc), reinterpret_cast<void*>(silent) );
		pthread_detach( handle );
		}//end if
}//end CheckForUpdates
