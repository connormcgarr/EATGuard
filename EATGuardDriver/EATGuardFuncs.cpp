/*++
*
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      EATGuardDriver/EATGuardFuncs.cpp
*
* @summary:   Functions that implement the actual functionality of the EATGuard driver.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#include "Defs.h"

/**
*
* @brief        Perform analysis on the target address.
* @param[in]    EatGuardInfo - Information about the EAT guard page violation.
* @param[in]	EatGuardOutput - Output to send to the EATGuardDll.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PerformEatGuardAnalysis (
    _In_ PEAT_GUARD_INPUT_DATA EatGuardInfo,
    _Out_ PEAT_GUARD_OUTPUT_DATA EatGuardOutput
    )
{
    NTSTATUS status;
    MEMORY_BASIC_INFORMATION memoryBasicInfo;
    MEMORY_REGION_INFORMATION memoryRegionInfo;
    PVOID rip;

    PAGED_PASSIVE();

    status = STATUS_SUCCESS;

    //
    // Extract what RIP was pointing to at the time of the exception.
    //
    rip = reinterpret_cast<PVOID>(EatGuardInfo->ContextRecord->Rip);

    //
    // Determine if RIP is RWX.
    //
    status = ZwQueryVirtualMemory(ZwCurrentProcess(),
                                  rip,
                                  static_cast<MEMORY_INFORMATION_CLASS>(MemoryBasicInformation),
                                  &memoryBasicInfo,
                                  sizeof(memoryBasicInfo),
                                  NULL);

    //
    // Error handling.
    //
    if (!NT_SUCCESS(status))
    {
        EatGuardOutput->AnalysisResult = EatGuardMemoryAnalysisFailed;

        goto Exit;
    }

    //
    // Has the page protection changed since the allocation was made?
    //
    if (memoryBasicInfo.Protect != memoryBasicInfo.AllocationProtect)
    {
        EatGuardOutput->HasPageProtectionChanged = TRUE;
    }
    else
    {
        EatGuardOutput->HasPageProtectionChanged = FALSE;
    }

    //
    // Was RIP pointing to RWX memory?
    //
    if (memoryBasicInfo.Protect & PAGE_EXECUTE_READWRITE)
    {
        EatGuardOutput->IsRipRwxMemory = TRUE;
    }
    else
    {
        EatGuardOutput->IsRipRwxMemory = FALSE;
    }

    //
    // Grab the base of the allocation of this memory,
    // the region size, and the commit size.
    //
    EatGuardOutput->RegionBaseAddress = memoryBasicInfo.AllocationBase;
    EatGuardOutput->MemoryRegionSize = memoryBasicInfo.RegionSize;

    //
    // Make another ZwQueryVirtualMemory call to determine if
    // RIP is backed by an image or if it is a private allocation.
    //
    status = ZwQueryVirtualMemory(ZwCurrentProcess(),
                                  rip,
                                  static_cast<MEMORY_INFORMATION_CLASS>(MemoryRegionInformationEx),
                                  &memoryRegionInfo,
                                  sizeof(memoryRegionInfo),
                                  NULL);

    //
    // Error handling.
    //
    if (!NT_SUCCESS(status))
    {
        EatGuardOutput->AnalysisResult = EatGuardMemoryAnalysisPartialFail;

        goto Exit;
    }

    //
    // Determine the type of allocation.
    //
    if (memoryRegionInfo.MappedImage)
    {
        EatGuardOutput->IsRipBackedByImage = TRUE;
    }
    else if (memoryRegionInfo.MappedDataFile)
    {
        EatGuardOutput->IsRipBackedByImage = TRUE;
    }
    else if (memoryRegionInfo.Private)
    {
        EatGuardOutput->IsRipBackedByImage = FALSE;
    }

    if (memoryRegionInfo.DirectMapped)
    {
        EatGuardOutput->IsRipMappedSection = TRUE;
    }

    //
    // Grab the commit size.
    //
    EatGuardOutput->MemoryCommtSize = memoryRegionInfo.CommitSize;

    //
    // Let the EATGuardDll know we succeeded in our analysis.
    //
    EatGuardOutput->AnalysisResult = EatGuardMemoryAnalysisSucceeded;

Exit:
    return status;
}