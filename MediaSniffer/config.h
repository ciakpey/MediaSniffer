#ifndef CTQY_CONFIG_H
#define CTQY_CONFIG_H

#include "platform.h"

#define MAX_ADAPTER_NAME 128
#define MAX_FILTERWORDS_LEN 4096

typedef struct
{
	char adapter[MAX_ADAPTER_NAME];
	u_int16_t dst_port; // tcp destination port, host order (for filtering)
	bool filter;
	char filterwords[MAX_FILTERWORDS_LEN];// words splitted with '|'
	bool filteridurl;
	bool checkupdate;
} Config;

void GetConfigFilePath( const char file[], char path[MAX_PATH] );

bool LoadConfig( const char file[], Config *cfg );
bool SaveConfig( const char file[], const Config *cfg );

#endif // CTQY_CONFIG_H
