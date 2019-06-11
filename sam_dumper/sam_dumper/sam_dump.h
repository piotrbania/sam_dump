#ifndef _CSAMDUMP
#define _CSAMDMP


#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include <ntsecapi.h>
#include <assert.h>

#include "privs.h"
#include "utils.h"

extern void flog_w(wchar_t		*wszUserName);

// taken from pwdump6
DECLARE_HANDLE(HUSER);
DECLARE_HANDLE(HSAM);
DECLARE_HANDLE(HDOMAIN);


#define USER_BUFFER_LENGTH					256
#define BUFFER_SIZE							1000
#define SAM_USER_INFO_PASSWORD_OWFS			0x12
#define SAM_HISTORY_COUNT_OFFSET			0x3c
#define SAM_HISTORY_NTLM_OFFSET				0x3c

typedef struct _sam_user_info 
{
    DWORD rid;
    LSA_UNICODE_STRING name;
} SAM_USER_INFO;

typedef struct _sam_user_enum 
{
    DWORD count;
    SAM_USER_INFO *users;
} SAM_USER_ENUM;

typedef struct _USERINFO
{
	char cHash[64];		// Stores NTLM and LanMan hash data
	wchar_t wszUser[256];	// Stores the user's name
} USERINFO, *LPUSERINFO;

#define SAM_USER_INFO_PASSWORD_OWFS 0x12
#define SAM_HISTORY_COUNT_OFFSET 0x3c
#define SAM_HISTORY_NTLM_OFFSET 0x3c

// Samsrv functions
typedef NTSTATUS (WINAPI *SamIConnectFunc) (DWORD, HSAM*, DWORD, DWORD);
typedef NTSTATUS (WINAPI *SamrOpenDomainFunc) (HSAM, DWORD dwAccess, PSID, HDOMAIN*);
typedef NTSTATUS (WINAPI *SamrOpenUserFunc) (HDOMAIN, DWORD dwAccess, DWORD, HUSER*);
typedef NTSTATUS (WINAPI *SamrEnumerateUsersInDomainFunc) (HDOMAIN, DWORD*, DWORD, SAM_USER_ENUM**, DWORD, PVOID);
typedef NTSTATUS (WINAPI *SamrQueryInformationUserFunc) (HUSER, DWORD, PVOID);
typedef HLOCAL   (WINAPI *SamIFree_SAMPR_USER_INFO_BUFFERFunc) (PVOID, DWORD);
typedef HLOCAL   (WINAPI *SamIFree_SAMPR_ENUMERATION_BUUFERFunc) (SAM_USER_ENUM*);
typedef NTSTATUS (WINAPI *SamrCloseHandleFunc) (HANDLE*);
typedef NTSTATUS (WINAPI *SamIGetPrivateData_t) (HUSER, DWORD *, DWORD *, DWORD *, PVOID *);
typedef NTSTATUS (WINAPI *SystemFunction025_t) (PVOID, DWORD*, BYTE[32] );
typedef NTSTATUS (WINAPI *SystemFunction027_t) (PVOID, DWORD*, BYTE[32] );


static SamIConnectFunc pSamIConnect = NULL;
static SamrOpenDomainFunc pSamrOpenDomain = NULL;
static SamrOpenUserFunc pSamrOpenUser = NULL;
static SamrQueryInformationUserFunc pSamrQueryInformationUser = NULL;
static SamrEnumerateUsersInDomainFunc pSamrEnumerateUsersInDomain = NULL;
static SamIFree_SAMPR_USER_INFO_BUFFERFunc pSamIFree_SAMPR_USER_INFO_BUFFER = NULL;
static SamIFree_SAMPR_ENUMERATION_BUUFERFunc pSamIFree_SAMPR_ENUMERATION_BUFFER = NULL;
static SamrCloseHandleFunc pSamrCloseHandle = NULL;
static SamIGetPrivateData_t pSamIGetPrivateData = NULL;
static SystemFunction025_t pSystemFunction025 = NULL;
static SystemFunction027_t pSystemFunction027 = NULL;



class CSamDump
{
	public:
		CSamDump();
		~CSamDump();

		BOOL	samdump(void);

	

	private:
		BOOL						get_all_apis(void);
		BOOL						sam_init(void);
		BOOL						sam_terminate(void);
		BOOL						sam_enumerate(void);
		BOOL						sam_dump_hash(PVOID hash);

		CPrivs						Privs;

		LSA_HANDLE					hLsa;
		PLSA_UNICODE_STRING			pSysName;
		POLICY_ACCOUNT_DOMAIN_INFO* pDomainInfo;
		NTSTATUS					rc, enumRc;
		HSAM						hSam;
		HDOMAIN						hDomain;
		HUSER						hUser;
		DWORD						dwEnum;
		DWORD						dwNumber;
		SAM_USER_ENUM				*pEnum;
		LSA_OBJECT_ATTRIBUTES		attributes;
		char						err_msg[512];


};



#endif
