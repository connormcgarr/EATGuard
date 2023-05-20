/*++
*
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      EATGuardDriver/IrpHandlers.cpp
*
* @summary:   IRP handlers for the EATGuard driver.
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
* @brief        Handle non-supported major functions.
* @param[in]    DriverObject - EATGuardDriver DEVICE_OBJECT.
* @param[in]	Irp - Associated IRP.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
_IRQL_requires_(PASSIVE_LEVEL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS
HandleMajorFunctionNotSupported (
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    PAGED_PASSIVE();

    UNREFERENCED_PARAMETER(DeviceObject);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_NOT_SUPPORTED;
}

/**
*
* @brief        Handle IRP_MJ_CREATE.
* @param[in]    DriverObject - EATGuardDriver DEVICE_OBJECT.
* @param[in]	Irp - Associated IRP.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
_IRQL_requires_(PASSIVE_LEVEL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS
HandleCreateMajorFunction (
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PAGED_PASSIVE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/**
*
* @brief        Handle IRP_MJ_CLOSE.
* @param[in]    DriverObject - EATGuardDriver DEVICE_OBJECT.
* @param[in]	Irp - Associated IRP.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
_IRQL_requires_(PASSIVE_LEVEL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS
HandleCloseMajorFunction (
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    PAGED_PASSIVE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/**
*
* @brief        Handle IRP_MJ_DEVICE_CONTROL.
* @param[in]    DriverObject - EATGuardDriver DEVICE_OBJECT.
* @param[in]	Irp - Associated IRP.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
_IRQL_requires_(PASSIVE_LEVEL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS
HandleIoctlMajorFunciton (
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpStackLocation;
    ULONG ioctlCode;
    PEAT_GUARD_INPUT_DATA inputBuffer;
    SIZE_T inputBufferLength;
    PEAT_GUARD_INPUT_DATA kernelEatGuardInputData;
    EAT_GUARD_OUTPUT_DATA kernelEatGuardOutputData;
    PEAT_GUARD_OUTPUT_DATA userSuppliedOutputBuffer;
    SIZE_T userSuppliedOutputBufferSize;

    PAGED_PASSIVE();

    UNREFERENCED_PARAMETER(DeviceObject);

    //
    // Default to unsuccessful in case we have to bail.
    //
    status = STATUS_UNSUCCESSFUL;

    //
    // Allocate memory for the copy of the EAT_GUARD_INPUT_DATA.
    //
    kernelEatGuardInputData = (PEAT_GUARD_INPUT_DATA)ExAllocatePool2(POOL_FLAG_PAGED,
                                                                     sizeof(EAT_GUARD_INPUT_DATA),
                                                                     EAT_GUARD_POOL_TAG);

    //
    // Error handling.
    //
    if (kernelEatGuardInputData == NULL)
    {
        goto Exit;
    }

    //
    // IoGetCurrentIrpStackLocation doesn't return an
    // error code.
    //
    irpStackLocation = IoGetCurrentIrpStackLocation(Irp);

    //
    // Cast the buffer to our expected input.
    //
    inputBuffer = (PEAT_GUARD_INPUT_DATA)irpStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;

    //
    // Get the input buffer size.
    //
    inputBufferLength = irpStackLocation->Parameters.DeviceIoControl.InputBufferLength;

    //
    // If the buffer isn't the size of our EAT_GUARD_INPUT_DATA
    // we know this isn't valid input and we can bail early.
    //
    if (inputBufferLength != sizeof(EAT_GUARD_INPUT_DATA))
    {
        goto Exit;
    }

    //
    // Get the IOCTL.
    //
    ioctlCode = irpStackLocation->Parameters.DeviceIoControl.IoControlCode;

    //
    // Get the output buffer supplied by the client.
    //
    userSuppliedOutputBuffer = reinterpret_cast<PEAT_GUARD_OUTPUT_DATA>(Irp->UserBuffer);

    //
    // Get the size of the output buffer specified by the client.
    //
    userSuppliedOutputBufferSize = irpStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

    //
    // Determine the IOCTL.
    //
    switch (ioctlCode)
    {
        case IOCTL_VERIFY_EAT_ACCESS:

            //
            // Ensure that the input buffer resides in user-mode.
            // We also need to verify that the underlying sub-structures
            // reside in user-mode.
            //
            __try
            {
                //
                // Verify the first "main" structure.
                //
                ProbeForRead(inputBuffer, inputBufferLength, sizeof(PVOID));

                //
                // Verify the exception records.
                //
                ProbeForRead(inputBuffer->ExceptionRecord, sizeof(EXCEPTION_RECORD), sizeof(PVOID));
                
                //
                // Verify more sub-structures.
                //
                ProbeForRead(inputBuffer->ExceptionRecord->ExceptionRecord, sizeof(EXCEPTION_RECORD), sizeof(PVOID));

                //
                // Verify the context record.
                //
                ProbeForRead(inputBuffer->ContextRecord, sizeof(CONTEXT), sizeof(PVOID));

                //
                // If we made it this far, go ahead and copy the memory to our kernel-mode copy.
                //
                RtlCopyMemory(kernelEatGuardInputData, inputBuffer, sizeof(EAT_GUARD_INPUT_DATA));
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                goto Exit;
            }

            //
            // Perform the actual EATGuard analysis.
            //
            status = PerformEatGuardAnalysis(kernelEatGuardInputData, &kernelEatGuardOutputData);

            //
            // Ensure that these output buffer resides in user-mode.
            // We also need to verify that the underlying sub-structures
            // reside in user-mode.
            //
            __try
            {
                //
                // Probe the output buffer to ensure its in user mode.
                //
                ProbeForWrite(userSuppliedOutputBuffer, sizeof(EAT_GUARD_OUTPUT_DATA), sizeof(PVOID));

                //
                // Copy the output from PerformEatGuardAnalysis to the user-supplied output buffer.
                //
                RtlCopyMemory(userSuppliedOutputBuffer, &kernelEatGuardOutputData, sizeof(EAT_GUARD_OUTPUT_DATA));
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                goto Exit;
            }

            break;

        default:
            break;
    }

Exit:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}