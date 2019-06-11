#include <stdio.h>
#include <conio.h>
#include <windows.h>


#include "sam_dump.h"


#define USE_DLL	1


#if USE_DLL == 1
BOOL WINAPI DllMain(
  __in  HINSTANCE hinstDLL,
  __in  DWORD fdwReason,
  __in  LPVOID lpvReserved
)
#else
int main(void)
#endif
{

#if USE_DLL == 0
	CSamDump Sam;
	DeleteFile(LOG_FILE);
	Sam.samdump();
#else
	
	CSamDump Sam;
	DeleteFile(LOG_FILE);
	

	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
			//OutputDebugString("IN LSAA\r\n");
			Sam.samdump();
			break;

		case DLL_PROCESS_DETACH:
			//OutputDebugString("OUT LSAA\r\n");
			break;
    }
	   return FALSE;

#endif

	return 0;
}