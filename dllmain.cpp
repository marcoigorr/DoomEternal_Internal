// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include "mem.h"
#include "offsets.hpp"
using namespace Offsets;
using namespace Offsets::pEnt;


DWORD WINAPI MainThread(HMODULE hModule)
{
    // Create Console
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    std::cout << "[+] Injection succeeded" << std::endl;

    // Get Module Base Addr
    uintptr_t moduleBase = (uintptr_t)GetModuleHandle(L"DOOMEternalx64vk.exe");
    std::cout << "[+] Module base: " << "0x" << std::uppercase << std::hex << moduleBase << std::endl;

    bool ejectDLL = false;
    bool isMemReadable = false;
    bool bAmmo = false, bHealth = false;   

    uintptr_t gMetrics = moduleBase + oGMetrics[0];
    uintptr_t aPlayerEnt = moduleBase + oPlayerEnt[0];
    std::cout << "[+] Game Metrics addr: " << "0x" << std::hex << gMetrics << std::endl;
    std::cout << "[+] Player Ent base addr: " << "0x" << std::hex << aPlayerEnt << std::endl;


    // Hack loop 
    while (!ejectDLL)
    {
        uintptr_t* ptrPlayerEnt = (uintptr_t*)(moduleBase + oPlayerEnt[0]);        

        if (GetAsyncKeyState(VK_F10) & 1) // testing
        {                    
        }

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
            std::cout << "[+] Changed Ammo hack status to -> " << std::uppercase << bAmmo << std::endl;

            if (bAmmo && !ejectDLL) // write and nop 
            {
                /* ----------------------------------------------- CAMPAIGN ----------------------------------------------------------- */

                uintptr_t* C_ptrChainsawCharge = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, oChainsawCharge);
                if (C_ptrChainsawCharge)
                    *(int*)C_ptrChainsawCharge = 3;

                uintptr_t* C_ptrCombatShotgunAmmo = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Campaign::oCombatShotgun);
                if (C_ptrCombatShotgunAmmo)
                    *(int*)C_ptrCombatShotgunAmmo = 24;

                uintptr_t* C_ptrHeavyRifleAmmo = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Campaign::oHeavyRifle);
                if (C_ptrHeavyRifleAmmo)
                    *(int*)C_ptrHeavyRifleAmmo = 180;

                uintptr_t* C_ptrPlasmaGun = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Campaign::oPlasmaGun);
                if (C_ptrPlasmaGun)
                    *(int*)C_ptrPlasmaGun = 250;

                uintptr_t* C_ptrRocketLauncher = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Campaign::oRocketLauncher);
                if (C_ptrRocketLauncher)
                    *(int*)C_ptrRocketLauncher = 13;
                
                uintptr_t* C_ptrBFG = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Campaign::oBFG);
                if (C_ptrBFG)
                    *(int*)C_ptrBFG = 60;
                
                uintptr_t* ptrSword = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Campaign::oSword);
                if (ptrSword)
                    *(float*)ptrSword = 3.0f;

                /* ----------------------------------------------- ANCIENT GODS ----------------------------------------------------------- */

                uintptr_t* AG1_ptrCombatShotgunAmmo = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, AncientGods::oCombatShotgun);
                if (AG1_ptrCombatShotgunAmmo)
                    *(int*)AG1_ptrCombatShotgunAmmo = 24;

                uintptr_t* AG1_ptrHeavyRifleAmmo = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, AncientGods::oHeavyRifle);
                if (AG1_ptrHeavyRifleAmmo)
                    *(int*)AG1_ptrHeavyRifleAmmo = 180;

                uintptr_t* AG1_ptrPlasmaGun = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, AncientGods::oPlasmaGun);
                if (AG1_ptrPlasmaGun)
                    *(int*)AG1_ptrPlasmaGun = 250;

                uintptr_t* AG1_ptrRocketLauncher = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, AncientGods::oRocketLauncher);
                if (AG1_ptrRocketLauncher)
                    *(int*)AG1_ptrRocketLauncher = 13;

                uintptr_t* AG1_ptrBFG = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, AncientGods::oBFG);
                if (AG1_ptrBFG)
                    *(int*)AG1_ptrBFG = 60;

                /* ----------------------------------------------- HORDE ----------------------------------------------------------- */

                uintptr_t* horde_ptrCombatShotgunAmmo = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Horde::oCombatShotgun);
                if (horde_ptrCombatShotgunAmmo)
                    *(int*)horde_ptrCombatShotgunAmmo = 24;

                uintptr_t* horde_ptrHeavyRifleAmmo = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Horde::oHeavyRifle);
                if (horde_ptrHeavyRifleAmmo)
                    *(int*)horde_ptrHeavyRifleAmmo = 180;

                uintptr_t* horde_ptrPlasmaGun = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Horde::oPlasmaGun);
                if (horde_ptrPlasmaGun)
                    *(int*)horde_ptrPlasmaGun = 250;

                uintptr_t* horde_ptrRocketLauncher = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Horde::oRocketLauncher);
                if (horde_ptrRocketLauncher)
                    *(int*)horde_ptrRocketLauncher = 13;

                uintptr_t* horde_ptrBFG = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Horde::oBFG);
                if (horde_ptrBFG)
                    *(int*)horde_ptrBFG = 60;

                // --- Nopping
                 
                // DOOMEternalx64vk.exe+1D24A03 - 89 7B 40 - mov [rbx+40],edi
                mem::Nop((BYTE*)(moduleBase + 0x1D24A03), 3);
                // DOOMEternalx64vk.exe+1D24A31 - 89 7B 40 - mov [rbx+40],edi
                mem::Nop((BYTE*)(moduleBase + 0x1D24A31), 3);
                // DOOMEternalx64vk.exe+1583451 - 89 82 28010000 - mov[rdx+00000128],eax (ammo value on screen)
                mem::Nop((BYTE*)(moduleBase + 0x1583451), 6);
                // DOOMEternalx64vk.exe+1561BD5 - 89 82 18010000 - mov [rdx+00000118],eax (warn low ammo)
                mem::Nop((BYTE*)(moduleBase + 0x1561BD5), 6);

                // DOOMEternalx64vk.exe+1906750 - F3 0F11 4B 08 - movss [rbx+08],xmm1 (update sword charge value)
                mem::Nop((BYTE*)(moduleBase + 0x1906750), 5);
            }
            else if (!bAmmo || ejectDLL) // write original code
            {
                mem::Patch((BYTE*)(moduleBase + 0x1D24A03), (BYTE*)"\x89\x7B\x40", 3);
                mem::Patch((BYTE*)(moduleBase + 0x1D24A31), (BYTE*)"\x89\x7B\x40", 3);
                mem::Patch((BYTE*)(moduleBase + 0x1583451), (BYTE*)"\x89\x82\x28\x01\x00\x00", 6);
                mem::Patch((BYTE*)(moduleBase + 0x1561BD5), (BYTE*)"\x89\x82\x18\x01\x00\x00", 6);

                mem::Patch((BYTE*)(moduleBase + 0x1906750), (BYTE*)"\xF3\x0F\x11\x4B\x08", 5);
            }  
        }

        // --- Health
        if (GetAsyncKeyState(VK_F2) & 1 || ejectDLL)
        {            
            bHealth = !bHealth;
            std::cout << "[+] Changed God mode hack status to -> " << bHealth << std::endl;

            if (bHealth && !ejectDLL) // write and nop
            {
                // DOOMEternalx64vk.exe+C93660 - F3 0F10 7C 24 48  - movss xmm7,[rsp+48]
                mem::Nop((BYTE*)(moduleBase + 0xC93660), 6);
                
                uintptr_t* ptrHealth = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, pEnt::oHealth);
                if (ptrHealth)
                    *(float*)ptrHealth = 200.0f;               
            }
            else if (!bHealth || ejectDLL)
            {
                mem::Patch((BYTE*)(moduleBase + 0xC93660), (BYTE*)"\xF3\x0F\x10\x7C\x24\x48", 6);
            }            
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

/*
// Check if memory is writable/readable (?? in cheatengine)
uintptr_t* ptrAll = (uintptr_t*)*ptrPlayerEnt + 0x0;
if (!IsBadWritePtr(ptrAll, sizeof(ptrAll)) && !IsBadReadPtr(ptrAll, sizeof(ptrAll)))
*/

// (OP CODE god mode) moduleBase + 0xC9364D - F3 0F11 44 1E 44 - movss [rsi+rbx+44],xmm0