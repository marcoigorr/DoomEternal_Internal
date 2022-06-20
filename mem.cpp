#include "pch.h"
#include "mem.h"

void mem::Patch(BYTE* dst, BYTE* src, unsigned int size)
{
	DWORD oldProtect;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(dst, src, size);
	VirtualProtect(dst, size, oldProtect, &oldProtect);
}

void mem::Nop(BYTE* dst, unsigned int size)
{
	DWORD oldProtect;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	memset(dst, 0x90, size);
	VirtualProtect(dst, size, oldProtect, &oldProtect);
}

uintptr_t mem::FindDMAAddy(uintptr_t addr, std::vector<unsigned int> offsets)
{
	uintptr_t cAddr = addr;
	for (unsigned int i = 0; i < offsets.size(); i++)
	{
		cAddr = *(uintptr_t*)cAddr;

		// Check if memory is writable (not ?? in cheatengine)
		if (IsBadReadPtr((uintptr_t*)cAddr, sizeof(cAddr)))		
			return 0;

		cAddr += offsets[i];
	}
	return cAddr;
}
