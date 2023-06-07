#pragma once
#include "NoCrt.h"





namespace ApiWrapper
{
    __forceinline    UNICODE_STRING InitUnicodeString(static const wchar_t* string_to_init)
    {

        UNICODE_STRING stringInit{ 0 };
        if (string_to_init)
        {
            stringInit.Length = NoCRT::string::wstrlen(string_to_init) * sizeof(wchar_t);
            stringInit.MaximumLength = stringInit.Length + 2;
            stringInit.Buffer = (wchar_t*)string_to_init;
        }
        return stringInit;

    }





    __forceinline  int CompareUnicodeString(UNICODE_STRING str_1, UNICODE_STRING str_2, bool case_int_sensitive = false)
    {

        //return 0 if equal
        if (case_int_sensitive)
        {
            return NoCRT::string::wstrcmp(str_1.Buffer, str_2.Buffer);
        }
        else
        {
            return NoCRT::string::wstricmp(str_1.Buffer, str_2.Buffer);
        }

    }


    __forceinline  bool  EqualUnicodeString(UNICODE_STRING str_1, UNICODE_STRING str_2, bool case_in_sensitive = false)
    {
        //return 1 if equal
        if (case_in_sensitive)
        {
            return !NoCRT::string::wstrcmp(str_1.Buffer, str_2.Buffer);
        }
        else
        {
            return !NoCRT::string::wstricmp(str_1.Buffer, str_2.Buffer);
        }
    }






    __forceinline  void FreeUnicodeString(UNICODE_STRING& str)
    {
        //just set buffer/Length

        /*
        in disassembly  RtlFreeUnicodeString use ExFreePoolWithTag wrf?
        */
        str.Buffer = 0;
        str.Length = 0;
        str.MaximumLength = 0;
    }


    


    void NTAPI MoveMemory(
        PVOID Destination,
        CONST VOID* Source,
        SIZE_T Length
    )
    {
        NoCRT::mem::memmove(Destination, Source, Length);
    }


    __forceinline  SIZE_T NTAPI  RtlCompareMemory(
        IN const VOID* Source1,
        IN const VOID* Source2,
        IN SIZE_T Length)
    {
        return NoCRT::mem::memicmp(Source1, Source2, Length);
    }

    __forceinline   VOID  NTAPI   ZeroMemory
    (
        PVOID Destination,
        SIZE_T Length)
    {
        NoCRT::mem::memset(Destination, Length, 0);
    }

    __forceinline  VOID NTAPI FillMemoryUlonglong
    (
        PVOID Destination,
        SIZE_T Length,
        ULONGLONG Fill)
    {
        PULONGLONG Dest = (PULONGLONG)Destination;
        SIZE_T Count = Length / sizeof(ULONGLONG);

        while (Count > 0)
        {
            *Dest = Fill;
            Dest++;
            Count--;
        }
    }

}
