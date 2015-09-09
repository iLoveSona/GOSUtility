#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0500
#include <windows.h>
#include <stdbool.h>
#include <stdlib.h>
#include "dirent.h"
#include <lauxlib.h>
#include <lua.h>
#include <winhttp.h>
#include <psapi.h>
#include <tlhelp32.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "lua5.1.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Psapi.lib")

const int VERSION = 3;
bool consoleOpen = false;
char scriptsHome[500];

void PrintFileVersion(lua_State *L, LPCTSTR szVersionFile)
{
	DWORD  verHandle;
	UINT   size = 0;
	LPBYTE lpBuffer = NULL;
	DWORD  verSize = GetFileVersionInfoSize(szVersionFile, &verHandle);

	if (verSize != 0)
	{
		LPSTR verData = malloc(verSize);

		if (GetFileVersionInfo(szVersionFile, verHandle, verSize, verData))
		{
			if (VerQueryValue(verData, "\\", (VOID FAR* FAR*)&lpBuffer, &size))
			{
				if (size)
				{
					VS_FIXEDFILEINFO *verInfo = (VS_FIXEDFILEINFO *)lpBuffer;
					if (verInfo->dwSignature == 0xfeef04bd)
					{

						// Doesn't matter if you are on 32 bit or 64 bit,
						// DWORD is always 32 bits, so first two revision numbers
						// come from dwFileVersionMS, last two come from dwFileVersionLS
						char result[sizeof(DWORD) * 4 + 4] = "";
						sprintf_s(result, sizeof(result), "%d.%d.%d.%d",
							(verInfo->dwFileVersionMS >> 16) & 0xffff,
							(verInfo->dwFileVersionMS >> 0) & 0xffff,
							(verInfo->dwFileVersionLS >> 16) & 0xffff,
							(verInfo->dwFileVersionLS >> 0) & 0xffff
							);
						printf(result);
						lua_pushstring(L, result);
					}
				}
			}
		}
		free(verData);
	}
}

void getProcessPathByName(lua_State *L, char* name)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	HANDLE processHandle = NULL;
	TCHAR filename[MAX_PATH];

	bool openProcessSuccess = false;
	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_stricmp(entry.szExeFile, name) == 0)
			{
				processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID);

				if (processHandle != NULL) {
					if (GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH) == 0) {
						printf("Failed to get module filename.\n");
						lua_pushnil(L);
					}
					else {
						printf("Module filename is: %s\n", filename);
						openProcessSuccess = true;
						PrintFileVersion(L, filename);
					}
					CloseHandle(processHandle);
				}
				else {
					printf("Failed to open process.\n");
					lua_pushnil(L);
				}
			}
		}
	}
	if (!openProcessSuccess)
	{
		lua_pushnil(L);
	}
	CloseHandle(snapshot);
}



static int getLolVersion(lua_State *L){
	getProcessPathByName(L, "League of Legends.exe");
	//getProcessPathByName(L, "notepad.exe");
	//lua_pushnil(L);
	return 1;
}

int endsWith(const char *str, const char *suffix)
{
    if (!str || !suffix)
        return 0;
    size_t lenstr = strlen(str);
    size_t lensuffix = strlen(suffix);
    if (lensuffix >  lenstr)
        return 0;
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

static int openConsole(){
    FreeConsole();
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    consoleOpen = true;
    return 1;
}

void pr(char* fmt, ...)
{
    if(!consoleOpen) openConsole();
    va_list args;
    va_start(args,fmt);
    vprintf(fmt,args);
    va_end(args);
}


static int version(lua_State *L){
    lua_pushnumber (L, VERSION);
    return 1;
}

static int listScripts(lua_State *L){
    DIR *dir;
    struct dirent *ent;

    if ((dir = opendir (scriptsHome)) != NULL) {
      int i=1;
    lua_newtable(L);
      while ((ent = readdir (dir)) != NULL) {
            if(!strcmp("testscript1.lua", ent->d_name)) continue;
            if(!strcmp("testscript2.lua", ent->d_name)) continue;
            if(!strcmp("testscript3.lua", ent->d_name)) continue;
            if(!endsWith(ent->d_name, ".lua")) continue;
            ent->d_name[strlen(ent->d_name)-4] = 0;
            char str[15];
            sprintf(str, "%d", i++);
            lua_pushstring(L, str);
            lua_pushstring(L, ent->d_name);
            lua_settable(L, -3);
      }
      closedir (dir);
    } else {
      pr("listscripts:error opening directory\n");
      lua_pushnil(L);
    }

    return 1;
}

static int print(lua_State *L){
    pr(luaL_checkstring(L, 1));
    pr("\n");
    return 0;
}

static int printn(lua_State *L){
    pr(luaL_checkstring(L, 1));
    return 0;
}

static int closeConsole(lua_State *L){
    HWND h=GetConsoleWindow();
    FreeConsole();
    SendMessage(h, WM_SYSCOMMAND, SC_CLOSE, 0);
    consoleOpen = false;
    return 0;
}

static int saveScript(lua_State *L){
    char filepath[600];
    strcpy(filepath, scriptsHome);
    strcat(filepath, luaL_checkstring(L, 1));
    strcat(filepath, ".lua");
    FILE *fp = fopen(filepath, "w+");
    if (fp != NULL){
        fputs(luaL_checkstring(L, 2), fp);
        fclose(fp);
        lua_pushboolean(L, true);
    }else{
        lua_pushboolean(L, false);
    }
    return 1;
}

static int request(lua_State *L){
	char buf[200000] ="";

	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;

	// Use WinHttpOpen to obtain a session handle.
	hSession = WinHttpOpen(L"WinHTTP Example/1.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	// Specify an HTTP server.
	if (hSession)
		hConnect = WinHttpConnect(hSession, L"raw.githubusercontent.com",
		INTERNET_DEFAULT_HTTPS_PORT, 0);

	// Create an HTTP request handle.
	char* lua_string = luaL_checkstring(L, 2);
	wchar_t wtext[300];
	mbstowcs(wtext, lua_string, strlen(lua_string) + 1);
	LPCWSTR url = wtext;
	if (hConnect)
		//hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/Inspired-gos/scripts/master/testscript1.lua",
		hRequest = WinHttpOpenRequest(hConnect, L"GET", url,
		NULL, WINHTTP_NO_REFERER,
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		WINHTTP_FLAG_SECURE);

	// Send a request.
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
		WINHTTP_NO_ADDITIONAL_HEADERS, 0,
		WINHTTP_NO_REQUEST_DATA, 0,
		0, 0);


	// End the request.
	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);

	// Keep checking for data until there is nothing left.
	if (bResults)
	{
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
			{
				printf("Error %u in WinHttpQueryDataAvailable.\n",
					GetLastError());
				lua_pushnil(L);
				return 1;
			}
				

			// Allocate space for the buffer.
			//pszOutBuffer = new char[dwSize + 1];
			pszOutBuffer = malloc(dwSize + 1);
			if (!pszOutBuffer)
			{
				printf("Out of memory\n");
				dwSize = 0;
				lua_pushnil(L);
				return 1;
			}
			else
			{
				// Read the data.
				ZeroMemory(pszOutBuffer, dwSize + 1);

				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
					dwSize, &dwDownloaded))
				{
					printf("Error %u in WinHttpReadData.\n", GetLastError());
					lua_pushnil(L);
					return 1;
				}
				else
					//printf("%s", pszOutBuffer);
					strcat(buf, pszOutBuffer);

				// Free the memory allocated to the buffer.
				//delete[] pszOutBuffer;
				free(pszOutBuffer);
			}
		} while (dwSize > 0);
	}

	// Report any errors.
	if (!bResults)
	{
		printf("Error %d has occurred.\n", GetLastError());
		lua_pushnil(L);
		return 1;
	}		

	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

    lua_pushstring(L, buf);
    memset(buf, 0, 200000);
    //memset(buf2, 0, 300);
    return 1;
}

static int mousePos(lua_State *L){
    POINT p;
    GetCursorPos(&p);
    lua_newtable(L);
    lua_pushnumber(L, p.x);
    lua_rawseti(L, -2, 1);
    lua_pushnumber(L, p.y);
    lua_rawseti(L, -2, 2);
    return 1;
}

static int resolution(lua_State *L){
    lua_newtable(L);
    lua_pushnumber(L, GetSystemMetrics(SM_CXSCREEN));
    lua_rawseti(L, -2, 1);
    lua_pushnumber(L, GetSystemMetrics(SM_CYSCREEN));
    lua_rawseti(L, -2, 2);
    return 1;
}


static const luaL_Reg GOSU[] = {{"version", version},
                                {"listScripts", listScripts},
                                {"print", print},
                                {"printn", printn},
                                {"closeConsole", closeConsole},
                                {"saveScript", saveScript},
                                {"request", request},
                                {"mousePos", mousePos},
                                {"resolution", resolution},
								{"getLolVersion", getLolVersion },
                                         {NULL, NULL}};
__declspec(dllexport)
int luaopen_GOSUtility (lua_State *L)
{
        strcpy(scriptsHome, getenv("APPDATA"));
        strcat(scriptsHome, "\\GamingOnSteroids\\LOL\\Scripts\\");
        luaL_register(L, "GOSU", GOSU);
        return 1;
}