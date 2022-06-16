// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include "mem.h"

DWORD WINAPI MainThread(HMODULE hModule)
{
    // Create Console
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    std::cout << "[+] Initializing" << std::endl;

    // Get Module Base Addr
    uintptr_t moduleBase = (uintptr_t)GetModuleHandle(L"DOOMEternalx64vk.exe");

    bool bAmmo = false;    

    // Hack loop 
    while (true)
    {
        // Key input
        if (GetAsyncKeyState(VK_INSERT) & 1)
        {
            break;
        }

        if (GetAsyncKeyState(VK_F1) & 1)
        {
            bAmmo = !bAmmo;
            if (bAmmo) // nop 
            { 
                // DOOMEternalx64vk.exe+1D24A03 - 89 7B 40 - mov [rbx+40],edi
                mem::Nop((BYTE*)(moduleBase + 0x1D24A03), 3);
                // DOOMEternalx64vk.exe+1D24A31 - 89 7B 40 - mov [rbx+40],edi
                mem::Nop((BYTE*)(moduleBase + 0x1D24A31), 3);
                // DOOMEternalx64vk.exe+1583451 - 89 82 28010000 - mov[rdx+00000128],eax (ammo value on screen)
                mem::Nop((BYTE*)(moduleBase + 0x1583451), 6);
                // DOOMEternalx64vk.exe+1561BD5 - 89 82 18010000 - mov [rdx+00000118],eax (warn low ammo)
                mem::Nop((BYTE*)(moduleBase + 0x1561BD5), 6);
            }
            else // write original code
            {
                mem::Patch((BYTE*)(moduleBase + 0x1D24A03), (BYTE*)"\x89\x7B\x40", 3);
                mem::Patch((BYTE*)(moduleBase + 0x1D24A31), (BYTE*)"\x89\x7B\x40", 3);
                mem::Patch((BYTE*)(moduleBase + 0x1583451), (BYTE*)"\x89\x82\x28\x01\x00\x00", 6);
                mem::Patch((BYTE*)(moduleBase + 0x1561BD5), (BYTE*)"\x89\x82\x18\x01\x00\x00", 6);
            }
        }
        Sleep(5);
    }
    // Cleanup / Eject
    fclose(f);
    FreeConsole();
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr));
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

