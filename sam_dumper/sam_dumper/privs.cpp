#include "privs.h"


CPrivs::CPrivs()
{

	HMODULE hNtdll = (HMODULE)GetModuleHandle("ntdll.dll");
	this->NtQueryInformationProcess	= (NTQUERYINFORMATIONPROCESS)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	this->NtSetInformationProcess		= (NTSETINFORMATIONPROCESS)GetProcAddress(hNtdll, "NtSetInformationProcess");
	assert(this->NtQueryInformationProcess);
	assert(this->NtSetInformationProcess);
}

CPrivs::~CPrivs()
{

}


/*
* Function enables or disables selected priviledge.
*/
#define SE_PRIVILEGE_ENABLED_BY_DEFAULT (0x00000001L)
#define SE_PRIVILEGE_ENABLED            (0x00000002L)


BOOL CPrivs::SetupPrivilege(char *priv_name, BOOL disable)
{
	DWORD				temp;
	HANDLE				hToken;
	LUID				Luid;
	TOKEN_PRIVILEGES	NewState;
	TOKEN_PRIVILEGES	LastState;
	char				err_msg[512];

	flog("%s: name = %s disable = %d\r\n", __FUNCTION__, priv_name, disable);

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		get_error_msg((char*)&err_msg);
		flog("%s: OpenProcessToken failed, error = %d (%s)\r\n", __FUNCTION__, GetLastError(), err_msg);
		return FALSE;
	}

	if (!LookupPrivilegeValue(0, priv_name, &Luid))
	{
		get_error_msg((char*)&err_msg);
		flog("%s: LookupPrivilegeValue failed, error = %d (%s)\r\n", __FUNCTION__, GetLastError(), err_msg); 
		CloseHandle(hToken);
		return FALSE;
	}

	flog("%s: Luid is = %08x\r\n", __FUNCTION__, Luid);

	NewState.Privileges[0].Luid       = Luid;
	NewState.Privileges[0].Attributes = 0;
    NewState.PrivilegeCount           = 1;
    
	AdjustTokenPrivileges(hToken, FALSE, &NewState, sizeof(TOKEN_PRIVILEGES), &LastState, &temp);
	if (GetLastError() != ERROR_SUCCESS)
	{
		get_error_msg((char*)&err_msg);
		flog("%s: AdjustTokenPrivileges failed, error = %d (%s)\r\n", __FUNCTION__, GetLastError(), err_msg); 
		CloseHandle(hToken);
		return FALSE;
	}

	if (LastState.Privileges[0].Attributes & SE_PRIVILEGE_ENABLED)
		flog("%s: this privilege was disabled\r\n", __FUNCTION__);
	else
		flog("%s: this privilege was enabled\r\n", __FUNCTION__);


	LastState.Privileges[0].Luid			= Luid;
    LastState.PrivilegeCount				= 1;
    LastState.Privileges[0].Attributes		|= SE_PRIVILEGE_ENABLED;
	if (disable)
		LastState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

   
	AdjustTokenPrivileges(hToken, FALSE, &LastState, temp, NULL, NULL );
	if (GetLastError() != ERROR_SUCCESS)
	{
		get_error_msg((char*)&err_msg);
		flog("%s: AdjustTokenPrivileges failed, error = %d (%s)\r\n", __FUNCTION__, GetLastError(), err_msg); 
		CloseHandle(hToken);
		return FALSE;
	}


	flog("%s: success!\r\n", __FUNCTION__);
	CloseHandle(hToken);
	return TRUE;
}


/*
* Function lists all privileges of the current process.
*/

BOOL CPrivs::ListPrivileges(void)
{
	HANDLE				hToken;
	DWORD				len;
	TOKEN_PRIVILEGES*	token_privs=NULL;
	char				err_msg[512];
	char				name[256];


	
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		get_error_msg((char*)&err_msg);
		flog("%s: OpenProcessToken failed, error = %d (%s)\r\n", __FUNCTION__, GetLastError(), err_msg);
		return FALSE;
	}

	GetTokenInformation(hToken, TokenPrivileges, token_privs, 0, &len);

	assert(len > 0);
	token_privs	=	(TOKEN_PRIVILEGES*)new BYTE[len+1];
	assert(token_privs);

	if (GetTokenInformation(hToken, TokenPrivileges, token_privs, len, &len))
	{
		for(int i = 0; i < token_privs->PrivilegeCount; i++)
		{
			DWORD s_len = sizeof(name);
			LookupPrivilegeName(NULL, &(token_privs->Privileges[i].Luid), name, &s_len); 

			flog("%s: PRIV%d: %s Attibutes: %x\r\n", __FUNCTION__, i, name, token_privs->Privileges[i].Attributes); 

		}
	}


	delete []token_privs;
	CloseHandle(hToken);
	return TRUE;
}


/*
* Function grants IO access to this usermode process.
* In other words direct IO access from ring3. Requires SE_TCB_PRIVILEGE.
*/


#define ProcessUserModeIOPL 16
typedef struct Iopl_t 
{
	ULONG Iopl;
} IOPLINFO, *PIOPLINFO;


BOOL	CPrivs::GrantIOAccess(void)
{
	NTSTATUS	st;
	IOPLINFO	io;


	io.Iopl	=	3;
	st = this->NtSetInformationProcess(
		(HANDLE)-1,
		ProcessUserModeIOPL,
		&io,
		sizeof(IOPLINFO));

	if (!NT_SUCCESS(st))
	{
		flog("%s: NtSetInformationProcess failed, error = %08x\r\n", __FUNCTION__, st);
		return FALSE;
	}

	flog("%s: access granted!\r\n", __FUNCTION__);
	return TRUE;
}