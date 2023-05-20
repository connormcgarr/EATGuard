/*++
*
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      EATGuardDriver/Defs.h
*
* @summary:   Various definitions for the EATGuard driver.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include "Shared.h"

//
// PAGED_PASSIVE macro.
// See: https://github.com/winsiderss/systeminformer/blob/2afc1ecc36eb2c7d844ed83960efe30e2a6fbf72/KSystemInformer/include/kph.h#L32
#define PAGED_PASSIVE()\
        PAGED_CODE()\
        NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL)

//
// Device name.
//
#define EAT_GUARD_DEVICE_NAME L"\\Device\\EATGuard"

//
// DosDevices name.
//
#define EAT_GUARD_DOS_DEVICES_NAME L"\\DosDevices\\EATGuard"

//
// Pool tag.
//
#define EAT_GUARD_POOL_TAG 0x67746145

//
// Undocumented enum values for ZwQueryVirtualMemory.
// See: https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntmmapi.h#L83
//
#define MemoryBasicInformation 0x0
#define MemoryWorkingSetInformation 0x1
#define MemoryMappedFilenameInformation 0x2
#define MemoryRegionInformation 0x3
#define MemoryWorkingSetExInformation 0x4
#define MemorySharedCommitInformation 0x5
#define MemoryImageInformation 0x6
#define MemoryRegionInformationEx 0x7
#define MemoryPrivilegedBasicInformation 0x8
#define MemoryEnclaveImageInformation 0x9
#define MemoryBasicInformationCapped 0xA
#define MemoryPhysicalContiguityInformation 0xB
#define MemoryBadInformation 0xC
#define MemoryBadInformationAllProcesses 0xD

//
// Undocumented MEMORY_REGION_INFORMATION structure.
// See: https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntmmapi.h#L138
//
#pragma warning( push )
#pragma warning( disable : 4201 )
typedef struct _MEMORY_REGION_INFORMATION
{
    PVOID AllocationBase;
    ULONG AllocationProtect;
    union
    {
        ULONG RegionType;
        struct
        {
            ULONG Private : 1;
            ULONG MappedDataFile : 1;
            ULONG MappedImage : 1;
            ULONG MappedPageFile : 1;
            ULONG MappedPhysical : 1;
            ULONG DirectMapped : 1;
            ULONG SoftwareEnclave : 1; // REDSTONE3
            ULONG PageSize64K : 1;
            ULONG PlaceholderReservation : 1; // REDSTONE4
            ULONG MappedAwe : 1; // 21H1
            ULONG MappedWriteWatch : 1;
            ULONG PageSizeLarge : 1;
            ULONG PageSizeHuge : 1;
            ULONG Reserved : 19;
        };
    };
    SIZE_T RegionSize;
    SIZE_T CommitSize;
    ULONG_PTR PartitionId; // 19H1
    ULONG_PTR NodePreference; // 20H1
} MEMORY_REGION_INFORMATION, * PMEMORY_REGION_INFORMATION;
#pragma warning( pop )

//
// Define valid IOCTLs for this driver.
//

//
// IOCTL_VERIFY_EAT_ACCESS - Used to verify the address which caused the
//                           guard page violation.
#define IOCTL_VERIFY_EAT_ACCESS \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

//
// Function definitions.
//
_IRQL_requires_(PASSIVE_LEVEL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS
HandleMajorFunctionNotSupported (
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS
HandleCreateMajorFunction (
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS
HandleCloseMajorFunction (
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS
HandleIoctlMajorFunciton (
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PerformEatGuardAnalysis (
    _In_ PEAT_GUARD_INPUT_DATA EatGuardInfo,
    _Out_ PEAT_GUARD_OUTPUT_DATA EatGuardOutput
    );