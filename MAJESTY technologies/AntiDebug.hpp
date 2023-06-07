#pragma once

#include "GetPID.h"
#include "Offset.hpp"

namespace AntiDebug
{

	namespace AntiUserModeAntiDebug
	{
		//Just check DebugPort in PEPROCESS
		__forceinline	bool PsIsProcessBeingDebugged(HANDLE procId)
		{


			uint64_t IsdebugPort = 0;
			if (procId)
			{
				PEPROCESS proc;



				if (NT_SUCCESS(PIDHelp::GetEProcessByProcId(procId, &proc)))
				{

					IsdebugPort = *(uint32_t*)((uint64_t)proc + Offset::debugOffset.DebugPort);



				}
			}
			return IsdebugPort;

		}







		//Just check NoDebugInherit  in PEPROCESS
		__forceinline	bool IsProcessDebugFlag(HANDLE procId)
		{
			/*
			NoDebugInherit safe  if  debugger detaches?
			*/


			processFlag2 IsDebugFlag{ 0 };
			if (procId)
			{
				PEPROCESS proc;


				if (NT_SUCCESS(PIDHelp::GetEProcessByProcId(procId, &proc)))
				{
					IsDebugFlag = (*(processFlag2*)((uint64_t)proc + Offset::debugOffset.NoDebugInherit));


				}
			}
			return IsDebugFlag.NoDebugInherit;

		}


		 
		  
		//Brute force find thread and check procId by thread
		__forceinline bool  HideManualThread(HANDLE procId)
		{

			bool IsSetHide = false;

			PETHREAD Thread;


			auto PsLookupThreadByThreadId = (t_PsLookupThreadByThreadId)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("PsLookupThreadByThreadId"));

			auto ObfDereferenceObject= (t_ObfDereferenceObject)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("ObfDereferenceObject"));

			for (size_t i = 0; i < 35000; i++)
			{


				if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)i, &Thread)))
				{

					auto proc = *(PEPROCESS*)((uint64_t)Thread + Offset::debugOffset.Process);

					if (proc)
					{
						auto procIdProcess = *(HANDLE*)((uint64_t)proc + PIDHelp::OffsetHelp::OffsetUniqueProcessId);

						if (procId == procIdProcess)
						{
							if ((*(uint32_t*)((uint64_t)Thread + Offset::debugOffset.HideFromDebugger) & 0x4) == 0)
							{
								*(uint32_t*)((uint64_t)Thread + Offset::debugOffset.HideFromDebugger) ^= 4;
								IsSetHide =  true;


							}
						}
					}
					ObfDereferenceObject(Thread);
				}

			}

			return IsSetHide;

		}

		//Brute force find thread and check procId by thread
		__forceinline bool  IsHardwareBreakpoint(HANDLE procId)
		{

			bool IsHardwareBreakpoint  = false;

			PETHREAD Thread;

			auto PsLookupThreadByThreadId = (t_PsLookupThreadByThreadId)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("PsLookupThreadByThreadId"));

			auto PsGetContextThread = (t_PsGetContextThread)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("PsGetContextThread"));
			auto ObfDereferenceObject = (t_ObfDereferenceObject )Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("ObfDereferenceObject"));

			for (size_t i = 0; i < 35000; i++)
			{


				if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)i, &Thread)))
				{

					auto proc = *(PEPROCESS*)((uint64_t)Thread + Offset::debugOffset.Process);

					if (proc)
					{
						auto procIdProcess = *(HANDLE*)((uint64_t)proc + PIDHelp::OffsetHelp::OffsetUniqueProcessId);

						if (procId == procIdProcess)
						{
							CONTEXT ctx;
							ctx.ContextFlags = CONTEXT_ALL; 
							if (NT_SUCCESS(PsGetContextThread(Thread,&ctx, KernelMode)))
							{
								if (ctx.Dr7 && ctx.Dr6)
								{
									IsHardwareBreakpoint = true;
								}
							
							} 
						}
					}
					ObfDereferenceObject(Thread);
				}

			}

			return IsHardwareBreakpoint;

		}

		

		__forceinline	bool IsUnderExplorer(HANDLE procId)
		{



			bool underExplorer = false;

			auto procIDExploler = PIDHelp::GetID(xorstr_("explorer.exe"));

			if (procId && procIDExploler)
			{
				PEPROCESS proc;

				if (NT_SUCCESS(PIDHelp::GetEProcessByProcId(procId, &proc)))
				{
					auto uniqIdProc = *(uint64_t*)((uint64_t)proc + Offset::debugOffset.InheritedFromUniqueProcessId);


					underExplorer = (uint64_t)procIDExploler != uniqIdProc;



				}
			}
			return underExplorer;

		}




		__forceinline bool IsInstrCallbacks(HANDLE procId)
		{
			uint64_t IsInstEnable = 0;
			if (procId)
			{
				PEPROCESS proc;


				if (NT_SUCCESS(PIDHelp::GetEProcessByProcId(procId, &proc)))
				{
					IsInstEnable = *(uint64_t*)((uint64_t)proc + Offset::debugOffset.InstrumentationCallback);


				}
			}
			return IsInstEnable != 0;
		}
		
		__forceinline bool BreakDebugPortMutex ()
		{

			/*
			
			BF 53 03 00 C0  0F 84  

			 
			\xBF\x53\x03\x00\xC0\x0F\x84 xxx?xxx

			48 8D 0D
			*/

			auto ProcessDebugPortMutexSig = (uint64_t)Util::FindPatternImage((PVOID)gl_baseNtoskrnl, xorstr_("PAGE"), xorstr_("\xBF\x53\x03\x00\xC0\x0F\x84"), xorstr_("xxx?xxx"));

			if (!ProcessDebugPortMutexSig)
			{
				Log("Can't find pattern \n");
				return false;
			}
			for (size_t i = 0; *(BYTE*)(ProcessDebugPortMutexSig + i) != 0xc3; i++) //wallking while not ret 
			{
				if (
					*(BYTE*)(ProcessDebugPortMutexSig + i) == 0x48 &&
					*(BYTE*)(ProcessDebugPortMutexSig + i + 1) == 0x8D &&
					*(BYTE*)(ProcessDebugPortMutexSig + i + 2) == 0x0D
					)
				{
					ProcessDebugPortMutexSig += i;
					auto ProcessDebugPortMutexFix = (uint64_t)Util::ResolveRelativeAddress((PVOID)ProcessDebugPortMutexSig, 3, 7);
 
					*( bool* )ProcessDebugPortMutexFix = 0;
					return true;
				}
			}

			return false;



		}

		__forceinline bool DisableValidAccessMask()
		{
			/*
			 Very thank's https://www.codenong.com/cs106696582/
				
				40 8A C5 4C 89 ? 24 ?

				\x40\x8A\xC5\xC4\x89\x00\x24\x00 xxxxx?x? 

			48 8B 05

			48 8B 05 A1 1F D9 FF                            mov     rax, cs:DbgkDebugObjectType // 7 

			48 8B 05 C6 9C 47 00                            mov     rax, cs:DbgkDebugObjectType // 10 
			
			*/
			auto DbgObjectPattern = (uint64_t)Util::FindPatternImage((PVOID)gl_baseNtoskrnl, xorstr_("PAGE"), xorstr_("\x40\x8A\xC5\x4C\x89\x00\x24\x00"), xorstr_("xxxxx?x?"));
		
			if (!DbgObjectPattern)
			{
				Log("Can't find pattern \n");
				return false;
			}

			for (size_t i = 0;*(BYTE*)(DbgObjectPattern + i) != 0xc3; i++) //wallking while not ret 
			{
				if (
					*(BYTE*)(DbgObjectPattern + i) ==  0x48 &&
					*(BYTE*)(DbgObjectPattern + i + 1 ) == 0x8b &&
					*(BYTE*)(DbgObjectPattern + i + 2) == 0x05
					)
				{
					DbgObjectPattern += i;
					auto DbgObjectPatternFixValue = (uint64_t)Util::ResolveRelativeAddress((PVOID)DbgObjectPattern, 3, 7);

					auto ObjectTypePointer = *(uint64_t*)(DbgObjectPatternFixValue);

					*(ULONG*)(ObjectTypePointer + 0x40 + 0x1c) = 0; // _OBJECT_TYPE -> TypeInfo - 0x40   ValidAccessMask - 0x1c 
					return true;
				}
			}
			
			return false;

			
		}
	}


	namespace AntiKernelDebug
	{


		//Just call DisableKernelDebug like mhyprot(AC genshin impact) https://www.godeye.club/2021/06/03/002-mhyprot-insider-callbacks.html
		__forceinline	bool DisableKernelDebug()
		{

			auto KdDisableDebugger = (t_KdDisableDebugger)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("KdDisableDebugger"));
			auto status = KdDisableDebugger();
			return	MurmurHash2A(status,7,7) != MurmurHash2A( STATUS_DEBUGGER_INACTIVE,7,7);

			// https://www.godeye.club/2021/06/03/002-mhyprot-insider-callbacks.html

		}

		//Call ZwSystemDebugControl with SysDbgBreakPoint
		__forceinline bool DebugTrigger()
		{

			//	https://pastebin.com/6kbt1Vka



			auto ZwSystemDebugControl = (t_ZwSystemDebugControl)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("ZwSystemDebugControl"));
			auto status = ZwSystemDebugControl(
				SysDbgBreakPoint,
				0,
				0,
				0,
				0,
				0
				);

		return MurmurHash2A(status, 10, 10) != MurmurHash2A(STATUS_DEBUGGER_INACTIVE, 10, 10);
		}

		//Call KdChangeOption like Vanguard  -> https://www.unknowncheats.me/forum/2798056-post2.html
		__forceinline	bool IsChangeOpthion()
		{

			auto KdChangeOption = (t_KdChangeOption)Util::GetProcAddress(gl_baseNtoskrnl, xorstr_("KdChangeOption"));
			auto status = KdChangeOption(KD_OPTION_SET_BLOCK_ENABLE, NULL, NULL, NULL, NULL, NULL);
			return MurmurHash2A(status, 6, 6) != MurmurHash2A(STATUS_DEBUGGER_INACTIVE, 6, 6);

		}



		//Check Some value ( more info -> https://shhoya.github.io/antikernel_kerneldebugging4.html	)
		__forceinline	bool CheckGlobalValue()
		{
			 

			auto kernelDebuggerPres = *(BYTE*)(0xFFFFF78000000000 + 0x02D4);

			 

			//	check value in KUSER_SHARED_DATA 

			if ((kernelDebuggerPres & 1) || (kernelDebuggerPres & 2))
			{
				return true;
			}
			auto  patternKdpBootedNodebug = (uint64_t)Util::FindPatternImage((PVOID)gl_baseNtoskrnl, xorstr_("PAGE"), xorstr_("\x4C\x8B\xD2\x83\x64\x24\x00\x00\x48\x83"), xorstr_("xxxxxx??xx"));

			if (patternKdpBootedNodebug)
			{

				/*
				4C 8B D2 83 64 24  ? ? 48 83

				\x4C\x8B\xD2\x83\x64\x24\x00\x00\x48\x83  xxxxxx??xx

				80 3D ? ? ? ?  00 // KdpBootedNodebug
				*/
				for (size_t i = 0; *(BYTE*)(patternKdpBootedNodebug + i) != 0xc3; i++) //wallking while not 1  ret 
				{
					if (
						*(BYTE*)(patternKdpBootedNodebug + i) == 0x80 &&
						*(BYTE*)(patternKdpBootedNodebug + i + 1) == 0x3D
						)
					{
						patternKdpBootedNodebug += i;
						auto KdpBootedNodebugFix = (uint64_t)Util::ResolveRelativeAddress((PVOID)patternKdpBootedNodebug, 2, 7);


						if (!*(bool*)KdpBootedNodebugFix)
						{
							return true;
						}

						break;

					}
				}


			}

			/*
			48 89 ? ? ?      45 33 C9    45 8B C2
			\x48\x89\x00\x00\x00\x45\x33\xC9\x45\x8B\xC2  xx???xxxxxx
			*/
			auto KdpReadVirtualMemoryPattern = (uint64_t)Util::FindPatternImage((PVOID)gl_baseNtoskrnl, xorstr_("PAGEKD"), xorstr_("\x48\x89\x00\x00\x00\x45\x33\xC9\x45\x8B\xC2"), xorstr_("xx???xxxxxx"));
			if (KdpReadVirtualMemoryPattern)
			{
				for (size_t i = 0; *(BYTE*)(KdpReadVirtualMemoryPattern + i) != 0xc3; i++) //wallking while not 1  ret 
				{

					if (
						*(BYTE*)(KdpReadVirtualMemoryPattern + i) == 0x4c &&
						*(BYTE*)(KdpReadVirtualMemoryPattern + i + 1) == 0x8D &&
						*(BYTE*)(KdpReadVirtualMemoryPattern + i + 2) == 0X0D
						)
					{
						KdpReadVirtualMemoryPattern += i;
						auto KdpContextFix = (uint64_t)Util::ResolveRelativeAddress((PVOID)KdpReadVirtualMemoryPattern, 3, 7);


						if (*(uint64_t*)KdpContextFix)
						{
							return true;
						}

						break;

					}
				}
			}
			
				/*
			F6 C1 02  74 ? 83   E1 FD         
			\xF6\xC1\x02\x74\x00\x83\xE1\xFD  xxxx?xxx
			
			2 pattern  48 8D 0D   

			40 53    48 83 EC 20   firs't byte
			*/
			auto KdpLowWriteContentpattern = (uint64_t)Util::FindPatternImage((PVOID)gl_baseNtoskrnl, xorstr_("PAGEKD"), xorstr_("\xF6\xC1\x02\x74\x00\x83\xE1\xFD"), xorstr_("xxxx?xxx"));
			if (KdpLowWriteContentpattern)
			{
				for (size_t i = 0; i < 90 || !((*(BYTE*)(KdpLowWriteContentpattern - i) == 0x40 && (*(BYTE*)(KdpLowWriteContentpattern - i + 1) == 0x53))); i++)
				{

					if (
						*(BYTE*)(KdpLowWriteContentpattern - i) == 0x48 &&
						*(BYTE*)(KdpLowWriteContentpattern - i + 1) == 0x8D &&
						*(BYTE*)(KdpLowWriteContentpattern - i + 2) == 0x0D
						)
					{
						KdpLowWriteContentpattern -= i;
						auto KdpBreakpointTableFix = (uint64_t)Util::ResolveRelativeAddress((PVOID)KdpLowWriteContentpattern, 3, 7);
					
						for (size_t j = 0; j <= 3 * 0x28; j++) // size struct 0x28 and we check 3 breakpoint 
						{
							if (*(BYTE*)(KdpBreakpointTableFix + j) !=0)
							{
								return true;
							}
						}
						break;
					}
				}
			}
			 

			/*
			7E 11  BA 01 00 00 00  48 8D 0D ? ? ? ? E8 ? ? ? FF


			\x7E\x11\xBA\x01\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\xFF

			xxxxxxxxxx????x???x
			*/
			auto KdpTimeSlipDpcRoutinePattern = (uint64_t)Util::FindPatternImage((PVOID)gl_baseNtoskrnl, xorstr_("PAGEKD"), xorstr_("\x7E\x11\xBA\x01\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\xFF"), xorstr_("xxxxxxxxxx????x???x"));
			if (KdpTimeSlipDpcRoutinePattern)
			{
				for (size_t i = 0; *(BYTE*)(KdpTimeSlipDpcRoutinePattern + i) != 0xc3; i++) //wallking while not 1  ret 
				{

					if (
						*(BYTE*)(KdpTimeSlipDpcRoutinePattern + i) == 0x48 &&
						*(BYTE*)(KdpTimeSlipDpcRoutinePattern + i + 1) == 0x8D &&
						*(BYTE*)(KdpTimeSlipDpcRoutinePattern + i + 2) == 0x0D
						)
					{
						KdpTimeSlipDpcRoutinePattern += i;
						auto KdpTimeSlipWorkItemFix = (uint64_t)Util::ResolveRelativeAddress((PVOID)KdpTimeSlipDpcRoutinePattern, 3, 7);

						for (size_t j = 0; j <= 0x20; j++) //size(WORK_QUEUE_ITEM) = 0x20 
						{
							if (*(BYTE*)(KdpTimeSlipWorkItemFix+ j))
							{
								return true;
							}

						}
						break;

					}
				}

			}

			/*
			? 38 ? ? ? ? ? 75 ? 45 ? ? ? 88 ? ? ? ? ? 48 8D
			\x00\x38\x00\x00\x00\x00\x00\x75\x00\x45\x00\x00\x00\x88\x00\x00\x00\x00\x00\x48\x8D
			?x?????x?x???x?????xx
			*/

			auto KdpDebuggerStructuresInitializedPattern = (uint64_t)Util::FindPatternImage((PVOID)gl_baseNtoskrnl, xorstr_("PAGEKD"), xorstr_("\x00\x38\x00\x00\x00\x00\x00\x75\x00\x45\x00\x00\x00\x88\x00\x00\x00\x00\x00\x48\x8D"), xorstr_("?x?????x?x???x?????xx"));
			if (KdpDebuggerStructuresInitializedPattern)
			{
				auto KdpDebuggerStructuresInitializedFix = (uint64_t)Util::ResolveRelativeAddress((PVOID)KdpDebuggerStructuresInitializedPattern, 3, 7);
				if (*(bool*)KdpDebuggerStructuresInitializedFix)
				{
					return true;
				}
			}
			return false;
		}
			
			

	}

}
