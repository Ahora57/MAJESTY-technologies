#pragma once
#include  "Offset.hpp"
#include "GetPID.h"



/*
	original https://github.com/notscimmy/pplib

	more info https://guidedhacking.com/threads/protected-processes-light-protected-processes.14968/

*/
namespace PplibEx
{

	__forceinline	void ProtectProcessByPID(HANDLE procId)
	{
		PEPROCESS proc; 
		 
		if (procId &&  NT_SUCCESS(PIDHelp::GetEProcessByProcId(procId, &proc)))
		{
			BYTE* pEProcess = (BYTE*)proc;
			uint8_t* pPPL = pEProcess + Offset::ppOffset.protection;

			uint64_t  version = Offset::GetWindowsNumber();
			if (MurmurHash2A(	version,7,7) == MurmurHash2A(WINDOWS_NUMBER_7,7,7))
				*(DWORD*)pPPL |= 1 << 0xB;
			else if (MurmurHash2A(version,8,8) == MurmurHash2A(WINDOWS_NUMBER_8,8,8))
				*pPPL = true;
			else if (MurmurHash2A(version,9,9) == MurmurHash2A(WINDOWS_NUMBER_8_1,9,9))
			{ 
				PS_PROTECTION protection;
				protection.Flags.Signer = PsProtectedSignerWinSystem;// = PsProtectedSignerMax for Windows 8.1
				protection.Flags.Type = PsProtectedTypeMax;
				*pPPL = protection.Level;
			}

			// process hacker can't sea PsProtectedTypeMax  and write Unknown	? WTF?!
			else if (MurmurHash2A(version,10,10) == MurmurHash2A(WINDOWS_NUMBER_10,10,10) || MurmurHash2A(version,11, 11) == MurmurHash2A(WINDOWS_NUMBER_11, 11, 11))
			{
				PS_PROTECTION protection; 
				protection.Flags.Signer = PsProtectedSignerMax;
				protection.Flags.Type = PsProtectedTypeMax;
				*pPPL = protection.Level;
			}
			 
		}


	}

}