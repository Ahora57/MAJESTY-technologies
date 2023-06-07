#pragma once 
#include <ntifs.h> 
#include <minwindef.h> 
#include <ntstrsafe.h>
#include <ntimage.h>
#include <cstdint>
 
#include "xorstr.h"


EXTERN_C __int64 __readmsr(
	int register
);
EXTERN_C void __cpuid(
	int cpuInfo[4],
	int function_id
);
EXTERN_C void __writemsr(
	unsigned long Register,
	unsigned __int64 Value
); 


 

#define WINDOWS_7 7600
#define WINDOWS_7_SP1 7601
#define WINDOWS_8 9200
#define WINDOWS_8_1 9600
#define WINDOWS_10_VERSION_THRESHOLD1 10240
#define WINDOWS_10_VERSION_THRESHOLD2 10586
#define WINDOWS_10_VERSION_REDSTONE1 14393
#define WINDOWS_10_VERSION_REDSTONE2 15063
#define WINDOWS_10_VERSION_REDSTONE3 16299
#define WINDOWS_10_VERSION_REDSTONE4 17134
#define WINDOWS_10_VERSION_REDSTONE5 17763
#define WINDOWS_10_VERSION_19H1 18362
#define WINDOWS_10_VERSION_19H2 18363
#define WINDOWS_10_VERSION_20H1 19041
#define WINDOWS_10_VERSION_20H2 19042
#define WINDOWS_10_VERSION_21H1 19043
#define WINDOWS_10_VERSION_21H2 19044
#define WINDOWS_11 22000


#define WINDOWS_NUMBER_7 7
#define WINDOWS_NUMBER_8 8
#define WINDOWS_NUMBER_8_1 9
#define WINDOWS_NUMBER_10 10
#define WINDOWS_NUMBER_11 11

#define IA32_P5_MC_ADDR_MSR		0x00000000
#define DEBUGCTL_LBR            0x01
#define DEBUGCTL_BTF            0x02
#define	IA32_TIME_STAMP_COUNTER 0x00000010
#define SMI_COUNT_MSR 0x00000034
#define IA32_MPERF_MSR 0x000000E7
#define IA32_APERF_MSR 0x000000E8
#define	MSR_P6M_LBSTK_TOS	0x1c9
#define	MSR_DEBUGCTL		0x1d9

static const uint64_t PMASK = (~0xfull << 8) & 0xfffffffffull;

#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK   0x00000001

#define 	LDR_IS_DATAFILE(handle)   (((ULONG_PTR)(handle)) & (ULONG_PTR)1)

#define 	LDR_DATAFILE_TO_VIEW(x)   ((PVOID)(((ULONG_PTR)(x)) & ~(ULONG_PTR)1))

#define OBJ_KERNEL_EXCLUSIVE           0x00010000L
#define OBJ_VALID_PRIVATE_ATTRIBUTES   0x00010000L
#define OBJ_ALL_VALID_ATTRIBUTES (OBJ_VALID_PRIVATE_ATTRIBUTES | OBJ_VALID_ATTRIBUTES)



DWORD64 gl_baseNtoskrnl = 0;

EXTERN_C POBJECT_TYPE* IoDriverObjectType;

#define PAGE_OFFSET_SIZE 12

#define FLS_MAXIMUM_AVAILABLE 128
#define TLS_MINIMUM_AVAILABLE 64
#define TLS_EXPANSION_SLOTS 1024

#define RTL_MAX_DRIVE_LETTERS 32


#define GDI_HANDLE_BUFFER_SIZE32    34
#define GDI_HANDLE_BUFFER_SIZE64    60

#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

 

typedef enum _LDR_DDAG_STATE
{
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping = 1,
	LdrModulesMapped = 2,
	LdrModulesWaitingForDependencies = 3,
	LdrModulesSnapping = 4,
	LdrModulesSnapped = 5,
	LdrModulesCondensed = 6,
	LdrModulesReadyToInit = 7,
	LdrModulesInitializing = 8,
	LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;


typedef enum _SYSDBG_COMMAND {
	SysDbgQueryModuleInformation,
	SysDbgQueryTraceInformation,
	SysDbgSetTracepoint,
	SysDbgSetSpecialCall,
	SysDbgClearSpecialCalls,
	SysDbgQuerySpecialCalls,
	SysDbgBreakPoint,
	SysDbgQueryVersion,
	SysDbgReadVirtual,
	SysDbgWriteVirtual,
	SysDbgReadPhysical,
	SysDbgWritePhysical,
	SysDbgReadControlSpace,
	SysDbgWriteControlSpace,
	SysDbgReadIoSpace,
	SysDbgWriteIoSpace,
	SysDbgReadMsr,
	SysDbgWriteMsr,
	SysDbgReadBusData,
	SysDbgWriteBusData,
	SysDbgCheckLowMemory,
	SysDbgEnableKernelDebugger,
	SysDbgDisableKernelDebugger,
	SysDbgGetAutoKdEnable,
	SysDbgSetAutoKdEnable,
	SysDbgGetPrintBufferSize,
	SysDbgSetPrintBufferSize,
	SysDbgGetKdUmExceptionEnable,
	SysDbgSetKdUmExceptionEnable,
	SysDbgGetTriageDump,
	SysDbgGetKdBlockEnable,
	SysDbgSetKdBlockEnable,
} SYSDBG_COMMAND, * PSYSDBG_COMMAND;

 
typedef union _PS_PROTECTION
{
	UCHAR Level;
	struct
	{
		int Type : 3;
		int Audit : 1;
		int Signer : 4;
	} Flags;
} PS_PROTECTION, * PPS_PROTECTION;

typedef enum _PS_PROTECTED_SIGNER
{
	PsProtectedSignerNone = 0,
	PsProtectedSignerAuthenticode = 1,
	PsProtectedSignerCodeGen = 2,
	PsProtectedSignerAntimalware = 3,
	PsProtectedSignerLsa = 4,
	PsProtectedSignerWindows = 5,
	PsProtectedSignerWinTcb = 6,
	PsProtectedSignerWinSystem = 7,
	PsProtectedSignerApp = 8,
	PsProtectedSignerMax = 9
} PS_PROTECTED_SIGNER;

typedef enum _PS_PROTECTED_TYPE
{
	PsProtectedTypeNone = 0,
	PsProtectedTypeProtectedLight = 1,
	PsProtectedTypeProtected = 2,
	PsProtectedTypeMax = 3

} PS_PROTECTED_TYPE;


struct DebugOffset
{
	uint32_t NoDebugInherit;
	uint32_t DebugPort;
	uint32_t HideFromDebugger;
	uint32_t InstrumentationCallback;
	uint32_t InheritedFromUniqueProcessId;
	uint32_t Process;

};


struct PprocOffset
{
	uint64_t protection;

};

struct processFlag2
{
	ULONG CreateReported : 1;                                         
	ULONG NoDebugInherit : 1;                                         
	ULONG ProcessExiting : 1;                                         
	ULONG ProcessDelete : 1;                                          
	ULONG ManageExecutableMemoryWrites : 1;                           
	ULONG VmDeleted : 1;                                              
	ULONG OutswapEnabled : 1;                                         
	ULONG Outswapped : 1;                                             
	ULONG FailFastOnCommitFail : 1;                                   
	ULONG Wow64VaSpace4Gb : 1;                                        
	ULONG AddressSpaceInitialized : 2;                                
	ULONG SetTimerResolution : 1;                                     
	ULONG BreakOnTermination : 1;                                     
	ULONG DeprioritizeViews : 1;                                      
	ULONG WriteWatch : 1;                                             
	ULONG ProcessInSession : 1;                                       
	ULONG OverrideAddressSpace : 1;                                   
	ULONG HasAddressSpace : 1;                                        
	ULONG LaunchPrefetched : 1;                                       
	ULONG Background : 1;                                             
	ULONG VmTopDown : 1;                                              
	ULONG ImageNotifyDone : 1;                                        
	ULONG PdeUpdateNeeded : 1;                                        
	ULONG VdmAllowed : 1;                                             
	ULONG ProcessRundown : 1;                                         
	ULONG ProcessInserted : 1;                                        
	ULONG DefaultIoPriority : 3;                                      
	ULONG ProcessSelfDelete : 1;                                      
	ULONG SetTimerResolutionLink : 1;                                 
};

 



struct CrossThreadFlags
{
	ULONG Terminated : 1;                                             
	ULONG ThreadInserted : 1;                                         
	ULONG HideFromDebugger : 1;                                       
	ULONG ActiveImpersonationInfo : 1;                                
	ULONG HardErrorsAreDisabled : 1;                                  
	ULONG BreakOnTermination : 1;                                     
	ULONG SkipCreationMsg : 1;                                        
	ULONG SkipTerminationMsg : 1;                                     
	ULONG CopyTokenOnOpen : 1;                                        
	ULONG ThreadIoPriority : 3;                                       
	ULONG ThreadPagePriority : 3;                                     
	ULONG RundownFail : 1;                                            
	ULONG UmsForceQueueTermination : 1;                               
	ULONG IndirectCpuSets : 1;                                        
	ULONG DisableDynamicCodeOptOut : 1;                               
	ULONG ExplicitCaseSensitivity : 1;                                
	ULONG PicoNotifyExit : 1;                                         
	ULONG DbgWerUserReportActive : 1;                                 
	ULONG ForcedSelfTrimActive : 1;                                   
	ULONG SamplingCoverage : 1;                                       
	ULONG ReservedCrossThreadFlags : 8;                               
};
 