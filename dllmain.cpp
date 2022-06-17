// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include "mem.h"
#include "offsets.hpp"
using namespace Offsets;


DWORD WINAPI MainThread(HMODULE hModule)
{
    // Create Console
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    std::cout << "[+] Initializing" << std::endl;

    // Get Module Base Addr
    uintptr_t moduleBase = (uintptr_t)GetModuleHandle(L"DOOMEternalx64vk.exe");
    std::cout << "[+] Module base: " << "0x" << std::uppercase << std::hex << moduleBase << std::endl;

    bool ejectDLL = false;
    bool bAmmo = false, bHealth = false;   

    uintptr_t gMetrics = moduleBase + oGMetrics[0];    
    uintptr_t playerEnt = moduleBase + oPlayerEnt[0];
    std::cout << "[+] Game Metrics addr: " << "0x" << std::hex << gMetrics << std::endl;
    std::cout << "[+] Player Ent base addr: " << "0x" << std::hex << playerEnt << std::endl;


    // Hack loop 
    while (!ejectDLL)
    {
        // Key input
        if (GetAsyncKeyState(VK_INSERT) & 1)
        {
            std::cout << "\n[+] Ejecting DLL..." << std::endl;
            ejectDLL = true;
        }

        // --- Ammo
        if (GetAsyncKeyState(VK_F1) & 1 || ejectDLL)
        {
            bAmmo = !bAmmo;
            if (bAmmo && !ejectDLL) // nop 
            {
                // DOOMEternalx64vk.exe+1D24A03 - 89 7B 40 - mov [rbx+40],edi
                mem::Nop((BYTE*)(moduleBase + 0x1D24A03), 3);
                // DOOMEternalx64vk.exe+1D24A31 - 89 7B 40 - mov [rbx+40],edi
                mem::Nop((BYTE*)(moduleBase + 0x1D24A31), 3);
                // DOOMEternalx64vk.exe+1583451 - 89 82 28010000 - mov[rdx+00000128],eax (ammo value on screen)
                mem::Nop((BYTE*)(moduleBase + 0x1583451), 6);
                // DOOMEternalx64vk.exe+1561BD5 - 89 82 18010000 - mov [rdx+00000118],eax (warn low ammo)
                mem::Nop((BYTE*)(moduleBase + 0x1561BD5), 6);

                // Combat Shotgun set to 16
                *(int*)mem::FindDMAAddy(playerEnt, pEnt::CombatShotgun::oAmmo) = 16;
                // Heavy Rifle set to 60
                *(int*)mem::FindDMAAddy(playerEnt, pEnt::HeavyRifle::oAmmo) = 60;
                // Chainsaw charge set to 3
                *(int*)mem::FindDMAAddy(playerEnt, pEnt::Chainsaw::oCharge) = 3;
            }
            else if (!bAmmo || ejectDLL) // write original code
            {
                mem::Patch((BYTE*)(moduleBase + 0x1D24A03), (BYTE*)"\x89\x7B\x40", 3);
                mem::Patch((BYTE*)(moduleBase + 0x1D24A31), (BYTE*)"\x89\x7B\x40", 3);
                mem::Patch((BYTE*)(moduleBase + 0x1583451), (BYTE*)"\x89\x82\x28\x01\x00\x00", 6);
                mem::Patch((BYTE*)(moduleBase + 0x1561BD5), (BYTE*)"\x89\x82\x18\x01\x00\x00", 6);
            }
            Sleep(5);
        }

        // --- Health
        if (GetAsyncKeyState(VK_F2) & 1)
        {
            bHealth = !bHealth;
        }

        if (bHealth)
        {
            *(int*)mem::FindDMAAddy(playerEnt, pEnt::oHealth) = 1137836032; // = 420
        }
    }
    // Cleanup/Eject
    fclose(f);
    FreeConsole();
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}
    
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
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

