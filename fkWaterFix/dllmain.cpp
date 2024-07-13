typedef struct IUnknown IUnknown;

#include <filesystem>

#include "include/MinHook.h"
#include "Hooks.h"

#include "include/InjectHook.h"

#pragma comment(lib,"user32.lib") 
#pragma comment(lib,"libs\\libMinHook.x86.lib")

std::string mainPath;

void __stdcall ColorTxtAfterHandler() {
    SetCurrentDirectoryA(mainPath.c_str());
}

int ColorTxtAfterLoadAddrRet = 0;
__declspec(naked) void ColorTxtAfterLoadHook() {

    __asm {
        call ColorTxtAfterHandler

        jmp ColorTxtAfterLoadAddrRet
    }
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        try {
        std::filesystem::path a = std::filesystem::current_path();
        mainPath = a.generic_string();

        DWORD ColorTxtAfterLoadAddr = Hooks::scanPattern2("ColorTxtAfterLoad", "E9 38 FE FF FF 68 40 51 5B 00 B9 B8 4F 5B 00 E8 93 2E 00 00 6A 08 E8 B4 8B F7 FF 89 45 B4 C6 45 FC 04 83 7D B4 00 74 0D 8B 4D B4 E8 C4 8E F7 FF 89 45 94 EB 07 C7 45 94 00 00 00 00 8B 4D 94 89 4D B0 C6 45 FC 00 8B 55 A8 8B 45 B0");
        ColorTxtAfterLoadAddrRet = Hooks::scanPattern2("ColorTxtAfterLoadReturn", "8B 4D E4 83 C1 01 89 4D E4 8B 55 E4 3B 55 DC 0F 8D B3 01 00 00 8B 45 E4 50 8B 4D A8 E8 31 87 F7 FF 89 45 D4 8B 4D D4 51");

        if(ColorTxtAfterLoadAddr != NULL && ColorTxtAfterLoadAddrRet != NULL)
            HookLib::InstallHook(reinterpret_cast<LPVOID>(ColorTxtAfterLoadAddr), &ColorTxtAfterLoadHook, HookLib::JMP_LONG);
        }
        catch(...)
        {

        }
    }
    break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

