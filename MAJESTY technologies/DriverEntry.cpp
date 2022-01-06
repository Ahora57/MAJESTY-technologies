
#include "AntiDebug.hpp" 
#include "AntiHypervisor.hpp"
#include "PplibEx.hpp"

//combine sections for  decrease size 

#pragma comment(linker, "/MERGE:.data=.text")

#pragma comment(linker, "/MERGE:.rdata=.text")

#pragma comment(linker, "/MERGE:.pdata=.text")

#pragma comment(linker, "/MERGE:INIT=.text")


//set ERW for present problem
#pragma comment(linker, "/SECTION:.text,EWR")
 


/*
For manual map driver just  give base address ntoskrnl in parameters  (like kdmapper)	https://github.com/TheCruZ/kdmapper/blob/c3b404298bf90b8fb2e74c2be783569dd0eaa06e/kdmapper/main.cpp#L105

Like :  https://cdn.discordapp.com/attachments/928741833117409421/928741933562601503/Set_parameter.png



For not manual map driver just use DriverObject (more info:  https://www.unknowncheats.me/forum/general-programming-and-reversing/427419-getkernelbase.html	)


*/

NTSTATUS DriverEntry(/* IN PDRIVER_OBJECT pDriverObject*/ DWORD64 baseNtoskrnl, IN PUNICODE_STRING pRegistryPath)
{





	gl_baseNtoskrnl = baseNtoskrnl;	//just set global value,because i lazy 


	PIDHelp::OffsetHelp::InitOffset(); // init value for get pid and other staff

	 

	static HANDLE procId = PIDHelp::GetID(xorstr_("SexyTest.exe"));



	if (Offset::GetOffset() )
	{
		/*

			⣿⣿⣷⡁⢆⠈⠕⢕⢂⢕⢂⢕⢂⢔⢂⢕⢄⠂⣂⠂⠆⢂⢕⢂⢕⢂⢕⢂⢕⢂
			⣿⣿⣿⡷⠊⡢⡹⣦⡑⢂⢕⢂⢕⢂⢕⢂⠕⠔⠌⠝⠛⠶⠶⢶⣦⣄⢂⢕⢂⢕
			⣿⣿⠏⣠⣾⣦⡐⢌⢿⣷⣦⣅⡑⠕⠡⠐⢿⠿⣛⠟⠛⠛⠛⠛⠡⢷⡈⢂⢕⢂
			⠟⣡⣾⣿⣿⣿⣿⣦⣑⠝⢿⣿⣿⣿⣿⣿⡵⢁⣤⣶⣶⣿⢿⢿⢿⡟⢻⣤⢑⢂
			⣾⣿⣿⡿⢟⣛⣻⣿⣿⣿⣦⣬⣙⣻⣿⣿⣷⣿⣿⢟⢝⢕⢕⢕⢕⢽⣿⣿⣷⣔
			⣿⣿⠵⠚⠉⢀⣀⣀⣈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣗⢕⢕⢕⢕⢕⢕⣽⣿⣿⣿⣿
			⢷⣂⣠⣴⣾⡿⡿⡻⡻⣿⣿⣴⣿⣿⣿⣿⣿⣿⣷⣵⣵⣵⣷⣿⣿⣿⣿⣿⣿⡿
			⢌⠻⣿⡿⡫⡪⡪⡪⡪⣺⣿⣿⣿⣿⣿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃
			⠣⡁⠹⡪⡪⡪⡪⣪⣾⣿⣿⣿⣿⠋⠐⢉⢍⢄⢌⠻⣿⣿⣿⣿⣿⣿⣿⣿⠏⠈
			⡣⡘⢄⠙⣾⣾⣾⣿⣿⣿⣿⣿⣿⡀⢐⢕⢕⢕⢕⢕⡘⣿⣿⣿⣿⣿⣿⠏⠠⠈
			⠌⢊⢂⢣⠹⣿⣿⣿⣿⣿⣿⣿⣿⣧⢐⢕⢕⢕⢕⢕⢅⣿⣿⣿⣿⡿⢋⢜⠠⠈
			⠄⠁⠕⢝⡢⠈⠻⣿⣿⣿⣿⣿⣿⣿⣷⣕⣑⣑⣑⣵⣿⣿⣿⡿⢋⢔⢕⣿⠠⠈
			⠨⡂⡀⢑⢕⡅⠂⠄⠉⠛⠻⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢋⢔⢕⢕⣿⣿⠠⠈
			⠄⠪⣂⠁⢕⠆⠄⠂⠄⠁⡀⠂⡀⠄⢈⠉⢍⢛⢛⢛⢋⢔⢕⢕⢕⣽⣿⣿⠠⠈
		*/
		
		
		Log("Is debug port ->\t %x\n", AntiDebug::AntiUserModeAntiDebug::PsIsProcessBeingDebugged(procId));

		Log("Is debug flag ->\t %x\n", AntiDebug::AntiUserModeAntiDebug::IsProcessDebugFlag(procId));

		Log("Isn't under Explorer ->\t %x\n", AntiDebug::AntiUserModeAntiDebug::IsUnderExplorer(procId));
		 
		Log("Is HardwareBreakpoint ->\t %x\n", AntiDebug::AntiUserModeAntiDebug::IsHardwareBreakpoint(procId));
		Log("Is find  thread and set HideFromDebugger ->\t %x\n", AntiDebug::AntiUserModeAntiDebug::HideManualThread(procId));
		 
		Log("Is instumenthion callbakc ->\t %x\n", AntiDebug::AntiUserModeAntiDebug::IsInstrCallbacks(procId));

		Log("Is find  ValidAccessMask ->\t %x\n",AntiDebug::AntiUserModeAntiDebug::DisableValidAccessMask());
		
		Log("Is find   DebugMutex ->\t %x\n", AntiDebug::AntiUserModeAntiDebug::BreakDebugPortMutex());


		PplibEx::ProtectProcessByPID(procId);
		
	}

	else
	{
		Log("Can't find offset!\n");
	}
	
	Log("KdChangeOpthion ->\t %x\n", AntiDebug::AntiKernelDebug::IsChangeOpthion());
	Log("Disable kernel debugger ->\t %x\n", AntiDebug::AntiKernelDebug::DisableKernelDebug());
	Log("ZwSystemDebugControl ->\t %x\n", AntiDebug::AntiKernelDebug::DebugTrigger());
	
	Log("Global value antidebug ->\t %x\n", AntiDebug::AntiKernelDebug::CheckGlobalValue());
	
	Log("Compare cpuid list ->\t %x\n", DetectHyp::compare_list_cpuid());
	Log("Cpuid is hypervisor ->\t %x\n", DetectHyp::cpuid_is_hypervisor());
	Log("Check virtualizathion lbr ->\t %x\n", DetectHyp::lbr_is_virtulazed());
	Log("Check stack lbr ->\t %x\n", DetectHyp::lbr_stask_is_virtulazed());


	Log("Time attack rdtsc ->\t %x\n", DetectHyp::time_attack_rdtsc());
	Log("Time attack with APERF ->\t %x\n", DetectHyp::time_attack_APERF());
	Log("Time attack with MPERF ->\t %x\n", DetectHyp::time_attack_MPERF());
	
	
	return STATUS_SUCCESS;



	
}
