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
    
    std::cout << "\n[+] F1 to enable Unlimited Ammo cheat" << std::endl;
    std::cout << "[+] F2 to enable God mode cheat" << std::endl;

    std::cout << "\n[!] Press INS button to eject cheats, DO NOT CLOSE THIS CONSOLE WINDOW (crash)\n" << std::endl;

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


                std::vector<uintptr_t*> ptrWeapons = {
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, oChainsawCharge),
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Campaign::oCombatShotgun),
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Campaign::oHeavyRifle),
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Campaign::oPlasmaGun),
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Campaign::oRocketLauncher),
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Campaign::oBFG),
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, AncientGods::oCombatShotgun),
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, AncientGods::oHeavyRifle),
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, AncientGods::oPlasmaGun),
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, AncientGods::oRocketLauncher),
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, AncientGods::oBFG),
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Horde::oCombatShotgun),
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Horde::oHeavyRifle),
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Horde::oPlasmaGun),
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Horde::oRocketLauncher),
                (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Horde::oBFG),
                };

                for (int i = 0; i < ptrWeapons.size(); i++)
                {
                    if (ptrWeapons[i])
                        *(int*)ptrWeapons[i] = 180;
                }

                uintptr_t* ptrSword = (uintptr_t*)mem::FindDMAAddy(aPlayerEnt, Campaign::oSword);
                if (ptrSword)
                    *(float*)ptrSword = 3.0f;
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