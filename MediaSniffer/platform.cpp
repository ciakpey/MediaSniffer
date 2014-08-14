#include "platform.h"

#ifdef OS_IS_LINUX
#include <stdlib.h>

char* itoa( int val, char *buf, int radix )
{
	const char aNumber[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char *p = buf;			/* pointer to traverse string */
	char *firstdig = buf;	/* pointer to first digit */
	char temp;			  /* temp char */
	div_t dv;

	if( val < 0 )
		{
		buf[0] = '-';
		++p;
		++firstdig;
		val = -val;
		}//end if

	dv.quot = val;
	do	{
		dv = div( (int)dv.quot, (int)radix );
		/* convert to ascii and store */
		*p++ = aNumber[dv.rem];
		} while( dv.quot > 0 );
		/* We now have the digit of the number in the buffer, but in reverse
		   order.  Thus we reverse them now. */

	*p-- = '\0';/* terminate string; p points to last digit */

	do	{
		temp = *p;
		*p = *firstdig;
		*firstdig = temp;   /* swap *p and *firstdig */
		--p;
		++firstdig;		 /* advance to next two digits */
		} while( firstdig < p ); /* repeat until halfway */

	return buf;
}//end itoa

Thread_h ThreadCreate( ThreadRoutine routine, void *arg )
{
	Thread_h handle = INVAL_THREAD;

	pthread_create( &handle, NULL, routine, arg );

	return handle;
}//end ThreadCreate

int ThreadWaitForExit( Thread_h handle )
{
	return pthread_join( handle, NULL );
}//end ThreadWaitForExit

void ThreadCloseHandle( Thread_h handle )
{
	pthread_detach( handle );
}//end ThreadCloseHandle

void MsSleep( int ms )
{
	usleep( ms * 1000 );
}//end MsSleep

#else // Windows

Thread_h ThreadCreate( ThreadRoutine routine, void *arg )
{
	return CreateThread( NULL, 0, routine, arg, 0, NULL );
}//end ThreadCreate

int ThreadWaitForExit( Thread_h handle )
{
	WaitForSingleObject( handle, INFINITE );
	return GetLastError();
}//end ThreadWaitForExit

void ThreadCloseHandle( Thread_h handle )
{
	CloseHandle( handle );
}//end ThreadCloseHandle

void MsSleep( int ms )
{
	Sleep( ms );
}//end MsSleep

#endif // OS
