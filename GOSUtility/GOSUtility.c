#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0500
#include <windows.h>
#include <stdbool.h>
#include <stdlib.h>
#include "dirent.h"
#include <lauxlib.h>
#include <lua.h>

const int VERSION = 2;
bool consoleOpen = false;
char scriptsHome[500];
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
    char cmd[1000];
    strcpy(cmd, scriptsHome);
    strcat(cmd, "Common\\curl.exe -ks ");
    if(!strcmp("github", luaL_checkstring(L, 1))) strcat(cmd, "https://raw.githubusercontent.com/");
    else if (!strcmp("opgg", luaL_checkstring(L, 1))) strcat(cmd, "http://op.gg/");
    else if (!strcmp("lolking", luaL_checkstring(L, 1))) strcat(cmd, "http://lolking.net/");
    else{
        pr("GOSUtility: forbidden server %s\n", luaL_checkstring(L, 1));
        lua_pushnil(L);
        return 1;
    }

    strcat(cmd, luaL_checkstring(L, 2));
    char buf[200000];
    char buf2[300];
    FILE *fp;

    if ((fp = _popen(cmd, "r")) == NULL) {
        lua_pushnil(L);
        return 1;
    }

    while (fgets(buf2, 300, fp) != NULL) {
            strcat(buf, buf2);
    }

    if(_pclose(fp))  {
        pr("Curl not found or exited with error status\n");
        lua_pushnil(L);
        return 1;
    }
    lua_pushstring(L, buf);
    memset(buf, 0, 200000);
    memset(buf2, 0, 300);
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
                                         {NULL, NULL}};
__declspec(dllexport)
int luaopen_GOSUtility (lua_State *L)
{
        strcpy(scriptsHome, getenv("APPDATA"));
        strcat(scriptsHome, "\\GamingOnSteroids\\LOL\\Scripts\\");
        luaL_register(L, "GOSU", GOSU);
        return 1;
}
