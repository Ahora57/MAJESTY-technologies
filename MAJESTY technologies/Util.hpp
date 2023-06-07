#pragma once
#include "NtApiDef.h"
#include "ApiWrapper.hpp"
#include "MurmurHash2A.h"

#define Log(x,...)  Util::Print(xorstr_(x), __VA_ARGS__)




namespace Util
{

	 


	
	
	__forceinline  uint64_t	GetProcAddress(const uintptr_t imageBase, const char* exportName) {

		if (!imageBase)
			return 0;

		if ( MurmurHash2A( reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_magic,10,10) != MurmurHash2A(0x5A4D,10,10))
			return 0;

		const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBase + reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_lfanew);
		const auto exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(imageBase + ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress);
		if (!exportDirectory)
			0;

		const auto exportedFunctions = reinterpret_cast<DWORD*>(imageBase + exportDirectory->AddressOfFunctions);
		const auto exportedNames = reinterpret_cast<DWORD*>(imageBase + exportDirectory->AddressOfNames);
		const auto exportedNameOrdinals = reinterpret_cast<UINT16*>(imageBase + exportDirectory->AddressOfNameOrdinals);

		for (size_t i{}; i < exportDirectory->NumberOfNames; ++i) {
			const auto functionName = reinterpret_cast<const char*>(imageBase + exportedNames[i]);
			if (NoCRT::string::stricmp(exportName, functionName) == 0) {
				return imageBase + exportedFunctions[exportedNameOrdinals[i]];

			}
		}

		return 0;
	}

	
	__forceinline  ULONG Print(const char* text, ...)
	{

		va_list(args);
		va_start(args, text);


		auto myvDbgPrintExWithPrefix = (t_vDbgPrintExWithPrefix)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("vDbgPrintExWithPrefix"));
		auto result = myvDbgPrintExWithPrefix(xorstr_("[sex technology] "), 0, 0, text, args);

		va_end(args);
		return result;

	}
	 

	__forceinline bool  CheckMask(const char* base, const char* pattern, const char* mask)
	{
		for (; *mask; ++base, ++pattern, ++mask)
		{
			if ('x' == *mask && *base != *pattern)
			{
				return false;
			}
		}

		return true;
	}


	__forceinline PVOID FindPattern(PVOID base, int length, const char* pattern, const char* mask)
	{
		length -= static_cast<int>(NoCRT::string::strlen(mask));
		for (auto i = 0; i <= length; ++i)
		{
			const auto* data = static_cast<char*>(base);
			const auto* address = &data[i];
			if (CheckMask(address, pattern, mask))
				return PVOID(address);
		}

		return nullptr;
	}

	__forceinline PVOID FindPatternImage(PVOID base, const char* secthionName, const char* pattern, const char* mask)
	{
		PVOID match = nullptr;

		auto* headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<char*>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
		auto* sections = IMAGE_FIRST_SECTION(headers);

		for (auto i = 0; i < headers->FileHeader.NumberOfSections; ++i)
		{
			auto* section = &sections[i];
			if ( NoCRT::mem::memcmp(section->Name, secthionName, NoCRT::string::strlen(secthionName)) == 0)
			{
				match = FindPattern(static_cast<char*>(base) + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
				if (match)
					break;
			}
		}

		return match;
	}

	__forceinline PVOID ResolveRelativeAddress(PVOID pvAddress, UINT64 qwOffset, UINT64 qwRelative)
	{
		ULONG ulRelativeAddress;
		NoCRT::mem::memmove(&ulRelativeAddress, (PVOID)((UINT64)pvAddress + qwOffset), sizeof(ULONG));
		return (PVOID)(ulRelativeAddress + (UINT64)pvAddress + qwRelative);
	}
}