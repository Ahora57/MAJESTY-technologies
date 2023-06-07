#pragma once
#include "Util.hpp"

namespace Offset
{
	DebugOffset  debugOffset;


	PprocOffset ppOffset;


	__forceinline uint64_t GetWindowsNumber()
	{

		RTL_OSVERSIONINFOW  lpVersionInformation{ 0 };

		lpVersionInformation.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);



		auto   RtlGetVersion = (t_RtlGetVersion)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("RtlGetVersion"));

		if (RtlGetVersion)
		{
			RtlGetVersion(&lpVersionInformation);
		}
		else
		{
			auto buildNumber = (PDWORD64)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("NtBuildNumber"));

			lpVersionInformation.dwBuildNumber = *buildNumber;
			lpVersionInformation.dwMajorVersion = *(ULONG*)0xFFFFF7800000026C;
			lpVersionInformation.dwMinorVersion = *(ULONG*)0xFFFFF78000000270;

		}

		if (lpVersionInformation.dwBuildNumber >= WINDOWS_11)
		{
			return WINDOWS_NUMBER_11;
		}


		else if (lpVersionInformation.dwBuildNumber >= WINDOWS_10_VERSION_THRESHOLD1 && lpVersionInformation.dwBuildNumber <= WINDOWS_10_VERSION_21H2)
		{
			return WINDOWS_NUMBER_10;

		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_8_1)
		{

			return WINDOWS_NUMBER_8_1;

		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_8)
		{

			return WINDOWS_NUMBER_8;


		}
		else if (lpVersionInformation.dwBuildNumber == WINDOWS_7_SP1 || lpVersionInformation.dwBuildNumber == WINDOWS_7)
		{

			return WINDOWS_NUMBER_7;

		}

	}



	__forceinline bool GetOffset()
	{


		RTL_OSVERSIONINFOW  lpVersionInformation{ 0 };




		lpVersionInformation.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);



		auto   RtlGetVersion = (t_RtlGetVersion)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("RtlGetVersion"));

		if (RtlGetVersion)
		{
			RtlGetVersion(&lpVersionInformation);
		}
		else
		{
			auto buildNumber = (PDWORD64)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("NtBuildNumber"));

			lpVersionInformation.dwBuildNumber = *buildNumber;
			lpVersionInformation.dwMajorVersion = *(ULONG*)0xFFFFF7800000026C;
			lpVersionInformation.dwMinorVersion = *(ULONG*)0xFFFFF78000000270;

		}


		if (lpVersionInformation.dwBuildNumber == WINDOWS_11)
		{

			debugOffset.HideFromDebugger = 0x560;
			debugOffset.NoDebugInherit = 0x464;
			debugOffset.DebugPort = 0x578;
			debugOffset.InstrumentationCallback = 0x3d8;
			debugOffset.InheritedFromUniqueProcessId = 0x540; 
			debugOffset.Process = 0x220;



			ppOffset.protection = 0x87a;




		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_21H1 || lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_21H2 ||
			lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_20H2 || lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_20H1)
			{

				debugOffset.HideFromDebugger = 0x510;
				debugOffset.DebugPort = 0x578;
				debugOffset.NoDebugInherit = 0x464;
				debugOffset.InstrumentationCallback = 0x3d8;
				debugOffset.InheritedFromUniqueProcessId = 0x540;  
				debugOffset.Process = 0x220;

				ppOffset.protection = 0x87a;

			}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_19H2 || lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_19H1)
		{
			debugOffset.HideFromDebugger = 0x6e0;
			debugOffset.DebugPort = 0x420;
			debugOffset.NoDebugInherit = 0x30c;
			debugOffset.InstrumentationCallback = 0x2d0;
			debugOffset.InheritedFromUniqueProcessId = 0x3e8;  
			debugOffset.Process = 0x220;

			ppOffset.protection = 0x6fa;


		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_REDSTONE5)
		{

			debugOffset.HideFromDebugger = 0x6d0;
			debugOffset.DebugPort = 0x420;
			debugOffset.NoDebugInherit = 0x304;
			debugOffset.InstrumentationCallback = 0x2c8;
			debugOffset.InheritedFromUniqueProcessId = 0x3e0; 
			debugOffset.Process = 0x220;

			ppOffset.protection = 0x6ca;



		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_REDSTONE4)
		{
			debugOffset.HideFromDebugger = 0x6d0;
			debugOffset.DebugPort = 0x420;
			debugOffset.NoDebugInherit = 0x304;
			debugOffset.InstrumentationCallback = 0x2c8;
			debugOffset.InheritedFromUniqueProcessId = 0x3e0; 
			debugOffset.Process = 0x220;

			ppOffset.protection = 0x6ca;



		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_REDSTONE3)
		{
			debugOffset.HideFromDebugger = 0x6d0;
			debugOffset.NoDebugInherit = 0x304;
			debugOffset.DebugPort = 0x420;
			debugOffset.InstrumentationCallback = 0x2c8;
			debugOffset.InheritedFromUniqueProcessId = 0x3e0; 
			debugOffset.Process = 0x220;

			ppOffset.protection = 0x6ca;


		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_REDSTONE2)
		{
			debugOffset.DebugPort = 0x420;
			debugOffset.NoDebugInherit = 0x304;
			debugOffset.InstrumentationCallback = 0x2c8;
			debugOffset.HideFromDebugger = 0x6c8;
			debugOffset.InheritedFromUniqueProcessId = 0x3e0; 
			debugOffset.Process = 0x220;

			ppOffset.protection = 0x6ca;



		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_REDSTONE1)
		{

			debugOffset.HideFromDebugger = 0x6c0;
			debugOffset.DebugPort = 0x420;
			debugOffset.NoDebugInherit = 0x304;
			debugOffset.InstrumentationCallback = 0x2c8;
			debugOffset.InheritedFromUniqueProcessId = 0x3e0; 
			debugOffset.Process = 0x220;

			ppOffset.protection = 0x6c2;




		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_THRESHOLD2)
		{
			debugOffset.HideFromDebugger = 0x6bc;
			debugOffset.DebugPort = 0x420;
			debugOffset.NoDebugInherit = 0x304;
			debugOffset.InstrumentationCallback = 0x2c8;
			debugOffset.InheritedFromUniqueProcessId = 0x3e0; 
			debugOffset.Process = 0x220;

			ppOffset.protection = 0x6b2;


		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_10_VERSION_THRESHOLD1)
		{
			debugOffset.HideFromDebugger = 0x6bc;
			debugOffset.DebugPort = 0x420;
			debugOffset.NoDebugInherit = 0x304;
			debugOffset.InstrumentationCallback = 0x2c8;
			debugOffset.InheritedFromUniqueProcessId = 0x3e0; 
			debugOffset.Process = 0x220;

			ppOffset.protection = 0x6aa;


		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_8_1)
		{

			debugOffset.HideFromDebugger = 0x6b4;
			debugOffset.DebugPort = 0x410;
			debugOffset.NoDebugInherit = 0x2fc;
			debugOffset.InstrumentationCallback = 0x2c0;
			debugOffset.InheritedFromUniqueProcessId = 0x3d0; 
			debugOffset.Process = 0x220;


			ppOffset.protection = 0x67A;


		}

		else if (lpVersionInformation.dwBuildNumber == WINDOWS_8)
		{

			

			debugOffset.DebugPort = 0x410;
			debugOffset.NoDebugInherit = 0x2fc;
			debugOffset.InstrumentationCallback = 0x2c0;
			debugOffset.HideFromDebugger = 0x42c;
			debugOffset.InheritedFromUniqueProcessId = 0x3d0; 
			debugOffset.Process = 0x220;

			ppOffset.protection = 0x648;



		}
		else if (lpVersionInformation.dwBuildNumber == WINDOWS_7_SP1 || lpVersionInformation.dwBuildNumber == WINDOWS_7)
		{

			debugOffset.HideFromDebugger = 0x448;
			debugOffset.DebugPort = 0x1f0;
			debugOffset.NoDebugInherit = 0x440;
			debugOffset.InstrumentationCallback = 0x100;
			debugOffset.InheritedFromUniqueProcessId = 0x290; 
			debugOffset.Process = 0x210;

			ppOffset.protection = 0x43C;

		}


		else
		{
			return false;
		}

		return true;

	}

}
