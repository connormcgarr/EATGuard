/*++
*
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      EATGuardDriver/Main.cpp
*
* @summary:   Entry point for the EATGuard driver.
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
* @brief        DriverUnload routine for driver unloads.
* @param[in]    DriverObject - EATGuardDriver DRIVER_OBJECT.
* @return       VOID
*
*/
_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_(PASSIVE_LEVEL)
VOID
DriverUnload (
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING dosDevicesName;

    PAGED_PASSIVE();

    if (DriverObject->DeviceObject)
    {
        //
        // Create a copy of the DosDevices name
        // in order to delete the symbolic link.
        //
        RtlInitUnicodeString(&dosDevicesName, EAT_GUARD_DOS_DEVICES_NAME);

        //
        // Delete the symbolic link.
        //
        IoDeleteSymbolicLink(&dosDevicesName);

        //
        // Delete the device object.
        //
        IoDeleteDevice(DriverObject->DeviceObject);
    }
    else
    {
        return;
    }
}

/**
* 
* @brief        EATGuardDriver entry point.
* @param[in]    DriverObject - EATGuardDriver DRIVER_OBJECT.
* @param[in]	RegistryPath - Pointer to string with driver registry key.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
* 
*/
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject;
    UNICODE_STRING deviceName;
    UNICODE_STRING dosDevicesName;

    PAGED_PASSIVE();

    UNREFERENCED_PARAMETER(RegistryPath);

    //
    // Set the driver unload routine.
    //
    DriverObject->DriverUnload = DriverUnload;

    //
    // Create the device name.
    //
    RtlInitUnicodeString(&deviceName, EAT_GUARD_DEVICE_NAME);

    //
    // Create the DosDevices name.
    //
    RtlInitUnicodeString(&dosDevicesName, EAT_GUARD_DOS_DEVICES_NAME);

    //
    // Create the device object.
    //
    status = IoCreateDevice(DriverObject,
                            0,
                            &deviceName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &deviceObject);

    //
    // Error handling.
    //
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    //
    // Create the symbolic link.
    //
    status = IoCreateSymbolicLink(&dosDevicesName, &deviceName);

    //
    // Error handling.
    //
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    //
    // Default all IRP handlers to HandleMajorFunctionNotSupported.
    //
    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        DriverObject->MajorFunction[i] = HandleMajorFunctionNotSupported;
    }

    //
    // Explicitly set the IRP_MJ_CREATE, IRP_MJ_CLOSE, and IRP_MJ_DEVICE_CONTROL
    // IRP handlers.
    //
    DriverObject->MajorFunction[IRP_MJ_CREATE] = HandleCreateMajorFunction;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = HandleCloseMajorFunction;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleIoctlMajorFunciton;

    //
    // IRP_MJ_READ/IRP_MJ_WRITE will method neither.
    // Therefore, do _not_ set the DO_BUFFERED_IO or DO_DIRECT_IO
    // bits in DeviceObject->Flags.
    //
    // Clear the DO_DEVICE_INITIALIZING flag.
    // See: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_device_object#do_device_initializing
    //
    deviceObject->Flags &= DO_DEVICE_INITIALIZING;

    return status;

Exit:
    return status;
}