#pragma once
#include "Struct.h"



 

typedef NTSTATUS (NTAPI* t_PsGetContextThread)
(
     PETHREAD Thread,
     PCONTEXT ThreadContext,
     KPROCESSOR_MODE Mode
);


typedef NTSTATUS(NTAPI* t_ZwSystemDebugControl)
(
    unsigned long ControlCode,
    void* InputBuffer,
    unsigned long InputBufferLength,
    void* OutputBuffer,
    unsigned long OutputBufferLength,
    unsigned long* pResultLength
    );

 
 



typedef NTSTATUS(NTAPI* t_KdDisableDebugger)();

typedef NTSTATUS(NTAPI* t_KdChangeOption)
(
    KD_OPTION Option,
    ULONG     InBufferBytes,
    PVOID     InBuffer,
    ULONG     OutBufferBytes,
    PVOID     OutBuffer,
    PULONG    OutBufferNeeded
    );


typedef ULONG(NTAPI* t_vDbgPrintExWithPrefix)(
    PCCH    Prefix,
    ULONG   ComponentId,
    ULONG   Level,
    PCCH    Format,
    va_list arglist
    );

typedef  NTSTATUS(NTAPI* t_RtlGetVersion)
(
    PRTL_OSVERSIONINFOW lpVersionInformation
    );


 

typedef  NTSTATUS(NTAPI* t_PsLookupThreadByThreadId)
(
    HANDLE   ThreadId,
    PETHREAD* Thread
    );


 
typedef LONG_PTR(NTAPI* t_ObfDereferenceObject )
(
    PVOID Object
    );

