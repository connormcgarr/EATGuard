/*++
*
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      EATGuardDriver/Shared.h
*
* @summary:   Shared data between user-mode client and EATGuardDriver.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#pragma once

//
// Enum of possible analysis results.
//
typedef enum _EAT_GUARD_ANALYSIS_RESULTS
{
    EatGuardMemoryAnalysisSucceeded = 0,
    EatGuardMemoryAnalysisFailed,
    EatGuardMemoryAnalysisPartialFail
} EAT_GUARD_ANALYSIS_RESULTS;

//
// Input buffer sent by user-mode client.
// This already will be pointer-sized aligned
// because the first member is a pointer.
//
typedef struct _EAT_GUARD_INPUT_DATA
{
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
} EAT_GUARD_INPUT_DATA, *PEAT_GUARD_INPUT_DATA;

//
// Output buffer received by user-mode client.
//
__declspec(align(sizeof(PVOID)))
typedef struct _EAT_GUARD_OUTPUT_DATA
{
    EAT_GUARD_ANALYSIS_RESULTS AnalysisResult;  // Was the analysis successuful?
    BOOLEAN IsRipRwxMemory;                     // IS RIP RWX memory?
    BOOLEAN IsRipBackedByImage;                 // Is RIP backed by an image?
    BOOLEAN IsRipMappedSection;                 // Is RIP part of a mapped section?
    BOOLEAN HasPageProtectionChanged;           // Did the page protection get updated since allocation?
    PVOID RegionBaseAddress;                    // The actual base address of the page
    SIZE_T MemoryRegionSize;                    // The size of the region.
    SIZE_T MemoryCommtSize;                     // Size of the commit.
} EAT_GUARD_OUTPUT_DATA, *PEAT_GUARD_OUTPUT_DATA;