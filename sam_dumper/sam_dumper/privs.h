#ifndef _CPRIVS
#define _CPRIVS

#include <stdio.h>
#include <conio.h>
#include <windows.h>
#include <assert.h>

#include "utils.h"

typedef LONG (NTAPI *NTQUERYINFORMATIONPROCESS)(HANDLE,DWORD,VOID*,DWORD,DWORD*);
typedef LONG (NTAPI *NTSETINFORMATIONPROCESS)(HANDLE,DWORD,VOID*,DWORD);

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

class CPrivs
{
	public:
		CPrivs();
		~CPrivs();

		BOOL	SetupPrivilege(char *priv_name, BOOL disable);
		BOOL	ListPrivileges(void);
		BOOL	GrantIOAccess(void);

	private:
		NTSETINFORMATIONPROCESS NtSetInformationProcess;
		NTQUERYINFORMATIONPROCESS NtQueryInformationProcess; 


};



#endif
