/*++
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      EATGuardDll/Defs.h
*
* @summary:   Various EATGuardDll definitions.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#pragma once
#include <Windows.h>
#include <stdio.h>
#include <assert.h>
#include "..\EATGuardDriver\Shared.h"

//
// Constants from ntddk.h needed
// to generate the IOCTL via CTL_CODE.
//
#define FILE_DEVICE_UNKNOWN 0x00000022
#define METHOD_NEITHER 3
#define FILE_ANY_ACCESS 0

//
// Macros.
//
#define ASSERT assert

//
// From ntddk.h
// 
// Macro definition for defining IOCTL and FSCTL function control codes.  Note
// that function codes 0-2047 are reserved for Microsoft Corporation, and
// 2048-4095 are reserved for customers.
//
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

//
// See: EATGuardDriver/Defs.h
// 
// IOCTL_VERIFY_EAT_ACCESS - Used to verify the address which caused the
//                           guard page violation.
#define IOCTL_VERIFY_EAT_ACCESS \
        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

//
// Structure defintions.
//
typedef struct _EAT_INFORMATION
{
    PVOID EatAddress;
    DWORD NumberOfFunctions;
} EAT_INFORMATION, * PEAT_INFORMATION;

//
// Function definitions.
//
BOOLEAN
LocateExportAddressTableKernel32 (
    _Out_ PEAT_INFORMATION EatAddress
    );

BOOLEAN
EnableEatGuardPage (
    _In_ PEAT_INFORMATION EatInformation,
    _Out_ DWORD OldProtect
    );

_Function_class_(PVECTORED_EXCEPTION_HANDLER)
LONG EatGuardVectoredExceptionHandler (
    _In_ _EXCEPTION_POINTERS* ExceptionInfo
    );

VOID
HandleGuardPageViolation (
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ PCONTEXT ContextRecord
    );

VOID
CreateEatGuardDriverHandle ();

BOOLEAN
SendEatInformationToEatGuardDriver (
    _In_ PEAT_GUARD_INPUT_DATA InputData
    );