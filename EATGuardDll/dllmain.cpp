/*++
*
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      EATGuardDll/dllmain.cpp
*
* @summary:   Entry point for EATGuardDLL.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#include "pch.h"
#include "Defs.h"
#include <malloc.h>

//
// Global variable to maintain the EAT_INFORMATION
// strucutre for KERNEL32.dll.
//
EAT_INFORMATION g_kernel32EatInformation;

//
// Global variable holding 
// the handle to the EATGuardDriver.
// 
// From EATGuardDll/Defs.h
//
HANDLE g_EatGuardDriverHandle;

/**
*
* @brief         Open a handle to the EATGuardDriver.
* @return        VOID
*
*/
VOID
CreateEatGuardDriverHandle ()
{
    HANDLE driverHandle;

    //
    // Call CreateFileW to get a handle.
    //
    driverHandle = CreateFileW(L"\\\\.\\EATGuard",
                               GENERIC_READ | GENERIC_WRITE,
                               0,
                               NULL,
                               OPEN_EXISTING,
                               0,
                               NULL);

    //
    // Error handling.
    //
    if (driverHandle == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[-] Error! GLE: 0x%I32x\n", GetLastError());

        //
        // Set the global variable to NULL.
        //
        g_EatGuardDriverHandle = nullptr;
    }

    //
    // Set the global variable.
    //
    g_EatGuardDriverHandle = driverHandle;
}

/**
*
* @brief         Send the specified EAT information to the EATGuardDriver.
* @param[in]     InputData - A pointer to the corresponding PEAT_GUARD_INPUT_DATA
* @return        VOID
*
*/
BOOLEAN
SendEatInformationToEatGuardDriver (
    _In_ PEAT_GUARD_INPUT_DATA InputData
    )
{
    DWORD bytesReturned;
    EAT_GUARD_OUTPUT_DATA outputData;

    bytesReturned = 0;

    //
    // We need the handle.
    //
    ASSERT(g_EatGuardDriverHandle != nullptr);

    //
    // Call DeviceIoControl.
    //
    if (!DeviceIoControl(g_EatGuardDriverHandle,
                         IOCTL_VERIFY_EAT_ACCESS,
                         InputData,
                         sizeof(EAT_GUARD_INPUT_DATA),
                         &outputData,
                         sizeof(outputData),
                         &bytesReturned,
                         NULL))
    {
        //
        // Error handling.
        //
        wprintf(L"[-] Error! Unable to interact with the EATGuardDriver! Error: 0x%I32X\n", GetLastError());

        return FALSE;
    }

    //
    // Check if there was an error.
    //
    if (outputData.AnalysisResult == EatGuardMemoryAnalysisFailed)
    {
        //
        // Print update.
        //
        wprintf(L"[-] Error! EATGuard analysis failed!\n");

        return FALSE;
    }

    //
    // Print update based on analysis.
    //
    wprintf(L"[+] EATGuard analysis complete!\n");
    wprintf(L"    [+] Target address: 0x%I64X\n", InputData->ContextRecord->Rip);

    //
    // RWX memory.
    //
    if (outputData.IsRipRwxMemory == TRUE)
    {
        wprintf(L"        [>] IsRipRwxMemory: TRUE\n");
    }
    else
    {
        wprintf(L"        [>] IsRipRwxMemory: FALSE\n");
    }

    //
    // Mapped via section.
    //
    if (outputData.IsRipMappedSection == TRUE)
    {
        wprintf(L"        [>] IsRipMappedSection: TRUE\n");
    }
    else
    {
        wprintf(L"        [>] IsRipMappedSection: FALSE\n");
    }

    //
    // Memory backed by image.
    //
    if (outputData.IsRipBackedByImage == TRUE)
    {
        wprintf(L"        [>] IsRipBackedByImage: TRUE\n");
    }
    else
    {
        wprintf(L"        [>] IsRipBackedByImage: FALSE\n");
    }

    //
    // From the time of allocation to time of the check,
    // did the permissions change?
    //
    if (outputData.HasPageProtectionChanged == TRUE)
    {
        wprintf(L"        [>] HasPageProtectionChanged: TRUE\n");
    }
    else
    {
        wprintf(L"        [>] HasPageProtectionChanged: FALSE\n");
    }

    //
    // Print everything else.
    //
    wprintf(L"        [>] RegionBaseAddress: 0x%I64X\n", reinterpret_cast<ULONG64>(outputData.RegionBaseAddress));
    wprintf(L"        [>] MemoryRegionSize: 0x%I64X\n", outputData.MemoryRegionSize);
    wprintf(L"        [>] MemoryCommtSize: 0x%I64X\n", outputData.MemoryCommtSize);

    return TRUE;
}

/**
*
* @brief         Handle a guard page violation.
* @param[in]     ExceptionRecord - A pointer to the corresponding EXCEPTION_RECORD
* @param[in]     ContextRecord - The CONTEXT of the exception.
* @return        VOID
*
*/
VOID
HandleGuardPageViolation (
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PCONTEXT ContextRecord
    )
{
    PEAT_GUARD_INPUT_DATA inputData = nullptr;

    //
    // Ensure we have valid input.
    //
    if ((ExceptionRecord == nullptr) || (ContextRecord == nullptr))
    {
        return;
    }

    //
    // Allocate our buffer we are sending to the EATGuardDriver on the heap.
    //
    inputData = reinterpret_cast<PEAT_GUARD_INPUT_DATA>(malloc(sizeof(EAT_GUARD_INPUT_DATA)));

    if (inputData == nullptr)
    {
        //
        // If we can't allocate memory, there is nothing we can do anyways
        // since we will exhaust the stack.
        //
        return;
    }

    //
    // inputData is made up of two very large structures.
    // Using it as a stack variable and copying memory into it
    // mashes the stack.
    // Instead, allocate the records on the heap. We will free them
    // at the end of this function.
    //
    inputData->ContextRecord = reinterpret_cast<PCONTEXT>(malloc(sizeof(CONTEXT)));
    inputData->ExceptionRecord = reinterpret_cast<PEXCEPTION_RECORD>(malloc(sizeof(EXCEPTION_RECORD)));

    //
    // Error handling.
    //
    if ((inputData->ContextRecord == nullptr) || (inputData->ExceptionRecord == nullptr))
    {
        //
        // If we can't allocate memory, there is nothing we can do anyways
        // since we will exhaust the stack.
        //
        return;
    }

    //
    // Copy the information into the input buffer.
    //
    RtlCopyMemory(inputData->ExceptionRecord, ExceptionRecord, sizeof(EXCEPTION_RECORD));
    RtlCopyMemory(inputData->ContextRecord, ContextRecord, sizeof(CONTEXT));

    //
    // Send this information off to be validated by the EATGuardDriver.
    //
    if (!SendEatInformationToEatGuardDriver(inputData))
    {
        //
        // For now, do nothing since we want to continue execution through
        // the single-step exception.
        //
    }

    //
    // By calling SendEatInformationToEatGuard, we blowup
    // the stack and ExceptionRecord and ContextRecord are no
    // longer in-scope. Set their contents back to normal.
    //
    RtlCopyMemory(ExceptionRecord, inputData->ExceptionRecord, sizeof(EXCEPTION_RECORD));
    RtlCopyMemory(ContextRecord, inputData->ContextRecord, sizeof(CONTEXT));

    //
    // Cause a single-step exception to occur after we
    // are done handling this guard page violation so
    // we can re-enable the guard page on the EAT. We
    // use the single-step violation to cause an exception
    // we know will occur later and we handle it via VEH
    // and checking for the code.
    // 
    // This is done by setting the Trap Flag (bit 8).
    //
    ContextRecord->EFlags = ContextRecord->EFlags | 0x100;
}

/**
*
* @brief         VEH function to handle guard page and single-step violations.
* @param[in]     ExceptionInfo- A pointer to an EXCEPTION_POINTERS structure that receives the exception record.
* @return        EXCEPTION_CONTINUE_EXECUTION if this is our guard page violation,
*                otherwise EXCEPTION_CONTINUE_SEARCH.
*
*/
_Function_class_(PVECTORED_EXCEPTION_HANDLER)
LONG EatGuardVectoredExceptionHandler (
    _In_ _EXCEPTION_POINTERS* ExceptionInfo
    )
{
    DWORD oldProtect;

    oldProtect = 0;

    //
    // If this is a guard page violation, perform EATGuard checks.
    // If this is a single-step violation, re-enable the guard page
    // on the EAT.
    //
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        HandleGuardPageViolation(ExceptionInfo->ExceptionRecord, ExceptionInfo->ContextRecord);

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        EnableEatGuardPage(&g_kernel32EatInformation, oldProtect);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/**
*
* @brief         Place a guard page on the specified EAT address.
* @param[in]     EatInformation - A pointer to information about the specified EAT.
* @param[out]    OldProtect - The old memory permissions of the EAT.
* @return        TRUE on success, FALSE on failure.
*
*/
BOOLEAN
EnableEatGuardPage (
    _In_ PEAT_INFORMATION EatInformation,
    _Out_ DWORD OldProtect
    )
{
    DWORD size;
    DWORD oldProtect;

    //
    // If we have no address, we are toast anyways.
    //
    ASSERT(EatInformation->EatAddress != nullptr);

    //
    // Take the number of functions found in the EAT
    // and multiply that by the size of a DWORD. Every 
    // entry in the EAT is just 1 DWORD which is added
    // to the base address of the image the EAT is in.
    // This means every "entry" in the EAT takes up
    // 4 bytes (1 DWORD)
    //
    size = (EatInformation->NumberOfFunctions * sizeof(DWORD));

    //
    // Turn the EAT into a guard page.
    //
    if (!VirtualProtect(EatInformation->EatAddress,
                        size,
                        PAGE_READONLY | PAGE_GUARD,
                        &oldProtect))
    {
        return FALSE;
    }

    OldProtect = oldProtect;

    return TRUE;
}

/**
*
* @brief         Locate's the address of the export address table (EAT) for KERNEL32.dll.
* @param[out]    EatInformation - A pointer to receive information about the KERNEL32.dll EAT.
* @return        TRUE if successful, FALSE otherwise.
*
*/
BOOLEAN
LocateExportAddressTableKernel32 (
    _Out_ PEAT_INFORMATION EatInformation
    )
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_EXPORT_DIRECTORY exportDirectory;
    ULONG_PTR baseAddress;

    baseAddress = reinterpret_cast<ULONG_PTR>(GetModuleHandleW(L"KERNEL32.dll"));

    //
    // Error handling.
    //
    if (baseAddress == NULL)
    {
        EatInformation->EatAddress = nullptr;
        EatInformation->NumberOfFunctions = 0;

        return FALSE;
    }

    //
    // This (obviously) is found at the very beginning
    // of the image. GetModuleHandleW returns the base
    // address of the current image (EATGuard.exe).
    dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress);

    //
    // e_lfanew is the offset to the IMAGE_NT_HEADERS from the base
    // address of the IMAGE_DOS_HEADERS.
    //
    ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(baseAddress + dosHeader->e_lfanew);

    //
    // Determine if we actually found the NT headers.
    //
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        EatInformation->EatAddress = nullptr;
        EatInformation->NumberOfFunctions = 0;

        return FALSE;
    }

    //
    // DataDirectory contains an array of structures. Each structure
    // can be found at a different index into an array. The first index
    // into the array is the export directory. We use & to capture the address
    // of this array index, which is the actual address of the export
    // directory.
    // 
    // The VirtualAddress member of the PIMAGE_EXPORT_DIRECTORY structure
    // is an offset from the base of the image. Which is why we add it here.
    // 
    // Better research is to look at how shellcode resolves Windows APIs
    // (AddressOfFunctions or AddressOfNameOrdinals) versus how legitimate
    // GetProcAddress callers do this. Maybe can just guard one of these
    // instead of the entire EAT.
    //
    exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(baseAddress + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    //
    // From the export directory, retrieve the AddressOfFunctions
    // (which is the export address table).
    //
    EatInformation->EatAddress = reinterpret_cast<PVOID>(baseAddress + exportDirectory->AddressOfFunctions);

    //
    // From the export directory, retrieve the number of functions
    // in the EAT.
    //
    EatInformation->NumberOfFunctions = exportDirectory->NumberOfFunctions;

    //
    // Assign the EatInformation structure to the global
    // variable.
    //
    g_kernel32EatInformation.EatAddress = EatInformation->EatAddress;
    g_kernel32EatInformation.NumberOfFunctions = EatInformation->NumberOfFunctions;

    return TRUE;
}

/**
*
* @brief        EATGuardDll Entry point.
* @param[in]    hModule - A handle to the DLL module.
* @param[in]    ul_reason_for_call - The reason code that indicates why the DLL entry-point function is being called.
* @param[in]    lpReserved - Reserved.
* @return       TRUE if successful, FALSE otherwise.
*
*/
BOOL
APIENTRY
DllMain (
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
    )
{
    EAT_INFORMATION kernel32EatInformation;
    DWORD eatOldMemoryProtection;
    PVOID vehHandle;

    eatOldMemoryProtection = 0;

    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        case DLL_THREAD_ATTACH:

            //
            // First thing we need to do is get the EATGuardDriver handle.
            //
            CreateEatGuardDriverHandle();

            //
            // Register our exception handler to handle guard page
            // violations. The first parameter here, if non-zero,
            // means this is the first handler registered.
            //
            vehHandle = AddVectoredExceptionHandler(1, EatGuardVectoredExceptionHandler);

            //
            // Error handling.
            //
            if (vehHandle == nullptr)
            {
                //
                // Print update.
                //
                wprintf(L"[-] Error! Unable to register to exception handler! Error: 0xI%32x\n", GetLastError());

                break;
            }

            //
            // Find the EAT address for KERNEL32.dll.
            //
            if (!LocateExportAddressTableKernel32(&kernel32EatInformation))
            {

                //
                // Print update.
                //
                wprintf(L"[-] Error! Unable to resolve the EAT address for KERNEL32.dll!\n");

                break;
            }

            //
            // Print update.
            //
            wprintf(L"[+] KERNEL32.dll EAT: 0x%p\n", kernel32EatInformation.EatAddress);
            wprintf(L"[+] Number of functions in the KERNEL32.dll EAT: %d\n", kernel32EatInformation.NumberOfFunctions);

            //
            // Enable the guard page.
            //
            if (!EnableEatGuardPage(&kernel32EatInformation, eatOldMemoryProtection))
            {
                //
                // Print update.
                //
                wprintf(L"[-] Error! Unable to create the guard page! 0x%I32x\n", GetLastError());

                break;

            }

        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
        }

    return TRUE;
}