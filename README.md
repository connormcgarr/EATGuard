# EATGuard
Implementation of an export address table protection mitigation, like Export Address Filtering (EAF)

## How It Works
This project is composed of three binaries that, when compiled, can be found in `EATGuard\bin\`. They are:
1. `EATGuardApplication.exe` - "Malicious" application that loads `EATGuardDll.dll` into the process and then executes some executable code (shellcode) which executes `notepad.exe`.
2. `EATGuardDll.dll` - DLL that provides a "bridge" between user-mode and kernel-mode. This DLL registers a Vectored Exception Handler (VEH) which sends detections of access to the `kernel32.dll` Export Address Table (EAT) to the `EATGuardDriver.sys` driver. This DLL allocates a guard page on the `kernel32.dll` EAT which causes an exception when the EAT is accessed within the `EATGuardApplication.exe` process space. This routes execution to the registered VEH which processes these exceptions and is responsible for continuing execution after analysis is completed.
3. `EATGuardDriver.sys` - Kernel-mode device driver which verifies access to the `kernel32.dll` EAT. Currently, as a POC, it checks if the memory which accesses `kernel32.dll` is backed by disk.

## How To Use
Please note that `EATGuardApplication.exe` loads `EATGuardDll.dll` from the relative path of `EATGuardApplication.exe`. This means both the `.exe` and `.dll` need to be in the same directory when executing. Please note also _do not_ run this project on a machine that has kernel debugging enabled. This can cause issues, as the `EATGuardDll.dll` uses a single-step exception for continuation of execution. Here is an example usage of the project:

```
C:\Users\ANON\Desktop>sc create EATGUARD type= kernel binPath= C:\Users\ANON\Desktop\EATGuardDriver.sys
[SC] CreateService SUCCESS

C:\Users\ANON\Desktop>sc start EATGUARD

SERVICE_NAME: EATGUARD
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 0
        FLAGS              :

C:\Users\ANON\Desktop>EATGuardApplication.exe
[+] KERNEL32.dll EAT: 0x00007FFB1D83F898
[+] Number of functions in the KERNEL32.dll EAT: 1678
[+] EATGuard analysis complete!
    [+] Target address: 0x24AA138005C
        [>] IsRipRwxMemory: TRUE
        [>] IsRipMappedSection: FALSE
        [>] IsRipBackedByImage: FALSE
        [>] HasPageProtectionChanged: FALSE
        [>] RegionBaseAddress: 0x24AA1380000
        [>] MemoryRegionSize: 0x1000
        [>] MemoryCommtSize: 0x1000
[+] EATGuard analysis complete!
    [+] Target address: 0x24AA138005F
        [>] IsRipRwxMemory: TRUE
        [>] IsRipMappedSection: FALSE
        [>] IsRipBackedByImage: FALSE
        [>] HasPageProtectionChanged: FALSE
        [>] RegionBaseAddress: 0x24AA1380000
        [>] MemoryRegionSize: 0x1000
        [>] MemoryCommtSize: 0x1000
[+] EATGuard analysis complete!
    [+] Target address: 0x24AA138008F
        [>] IsRipRwxMemory: TRUE
        [>] IsRipMappedSection: FALSE
        [>] IsRipBackedByImage: FALSE
        [>] HasPageProtectionChanged: FALSE
        [>] RegionBaseAddress: 0x24AA1380000
        [>] MemoryRegionSize: 0x1000
        [>] MemoryCommtSize: 0x1000
[+] EATGuard analysis complete!
    [+] Target address: 0x24AA138009B
        [>] IsRipRwxMemory: TRUE
        [>] IsRipMappedSection: FALSE
        [>] IsRipBackedByImage: FALSE
        [>] HasPageProtectionChanged: FALSE
        [>] RegionBaseAddress: 0x24AA1380000
        [>] MemoryRegionSize: 0x1000
        [>] MemoryCommtSize: 0x1000
[+] EATGuard analysis complete!
    [+] Target address: 0x24AA13800A2
        [>] IsRipRwxMemory: TRUE
        [>] IsRipMappedSection: FALSE
        [>] IsRipBackedByImage: FALSE
        [>] HasPageProtectionChanged: FALSE
        [>] RegionBaseAddress: 0x24AA1380000
        [>] MemoryRegionSize: 0x1000
        [>] MemoryCommtSize: 0x1000

(...)TRUNCATED(...)
```

This project is a POC which mimics the functionality of [Export Address Filtering](https://windows-internals.com/an-exercise-in-dynamic-analysis/).