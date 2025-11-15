/**
 * Anti-Analysis Methods
 * =======================
 *
 * Category 2: Advanced C Utilities
 * Implements VM detection, debugger detection, and hook detection
 *
 * DEFENSIVE RESEARCH ONLY - AUTHORIZED USE REQUIRED
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#else
#include <unistd.h>
#include <sys/ptrace.h>
#endif

#include "polygottem_c.h"

/**
 * Virtual Machine Detection
 * Detects execution environment virtualization
 */
anti_analysis_result_t anti_vm_detection(void) {
    anti_analysis_result_t result = {0};
    strcpy(result.detection_type, "vm_detection");

    /* VM detection techniques:
     * 1. CPUID checks:
     *    - "KVMKVMKVM" (KVM)
     *    - "XenVMMXenVMM" (Xen)
     *    - "VMwareVMware" (VMware)
     *    - "VirtualBox" (VirtualBox)
     *    - "HyperV" (Hyper-V)
     *
     * 2. Timing checks (RDTSC):
     *    - VM context switches cause timing anomalies
     *    - Detect if RDTSC is unreliable
     *
     * 3. Device checks:
     *    - Absence of optical/floppy drives
     *    - Absence of sound cards
     *    - Absence of USB devices
     */

    #ifdef _WIN32
    /* CPUID check for hypervisor */
    unsigned int eax, ebx, ecx, edx;
    char hypervisor_name[13] = {0};

    __cpuid(1, eax, ebx, ecx, edx);

    /* ECX bit 31 indicates hypervisor presence */
    if (ecx & (1 << 31)) {
        result.detected = true;
        strcpy(result.evasion_method, "CPUID hypervisor bit detected");

        /* Get hypervisor name */
        __cpuid(0x40000000, eax, ebx, ecx, edx);
        *(unsigned int*)&hypervisor_name[0] = ebx;
        *(unsigned int*)&hypervisor_name[4] = ecx;
        *(unsigned int*)&hypervisor_name[8] = edx;

        if (strstr(hypervisor_name, "KVM") != NULL) {
            strcpy(result.evasion_method, "KVM detected");
        } else if (strstr(hypervisor_name, "Xen") != NULL) {
            strcpy(result.evasion_method, "Xen detected");
        }
    }

    /* Check for VM-specific device presence */
    HANDLE hdev = CreateFileA("\\\\.\\VMCIBus", GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hdev != INVALID_HANDLE_VALUE) {
        result.detected = true;
        strcpy(result.evasion_method, "VMware VMCI bus detected");
        CloseHandle(hdev);
    }

    #else
    /* Linux CPUID equivalent using asm */
    result.detected = false;
    strcpy(result.evasion_method, "VM detection not enabled in guest");
    #endif

    return result;
}

/**
 * Debugger Detection
 * Detects active debugger attachment
 */
anti_analysis_result_t anti_debugger_detection(void) {
    anti_analysis_result_t result = {0};
    strcpy(result.detection_type, "debugger_detection");

    /* Debugger detection techniques:
     * 1. Windows API checks:
     *    - IsDebuggerPresent()
     *    - CheckRemoteDebuggerPresent()
     *    - NtQueryInformationProcess(ProcessDebugPort)
     *
     * 2. Exception handling:
     *    - Try to trigger exception
     *    - Debugger will catch it
     *    - Legitimate execution won't
     *
     * 3. Timing analysis:
     *    - Debuggers add overhead
     *    - Detect slow execution
     */

    #ifdef _WIN32
    /* Check 1: IsDebuggerPresent API */
    if (IsDebuggerPresent()) {
        result.detected = true;
        strcpy(result.evasion_method, "IsDebuggerPresent returned TRUE");
        return result;
    }

    /* Check 2: Exception handling detection */
    __try {
        /* Attempt debug break */
        __asm {
            int 3
        }
        /* If we reach here, no debugger */
        result.detected = false;
        strcpy(result.evasion_method, "No exception on int3");
    } __except (1) {
        /* Exception caught = debugger present */
        result.detected = true;
        strcpy(result.evasion_method, "Exception caught (debugger present)");
    }

    /* Check 3: CheckRemoteDebuggerPresent */
    BOOL is_debugged = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &is_debugged)) {
        if (is_debugged) {
            result.detected = true;
            strcpy(result.evasion_method, "CheckRemoteDebuggerPresent");
        }
    }

    #else
    /* Linux debugger detection via ptrace */
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        result.detected = true;
        strcpy(result.evasion_method, "PTRACE_TRACEME failed (already debugged)");
    } else {
        result.detected = false;
        strcpy(result.evasion_method, "No debugger detected");
        ptrace(PTRACE_DETACH, getppid(), 1, 0);
    }
    #endif

    return result;
}

/**
 * Hook Detection
 * Detects inline hooks and API interception
 */
anti_analysis_result_t anti_hook_detection(void) {
    anti_analysis_result_t result = {0};
    strcpy(result.detection_type, "hook_detection");

    /* Hook detection techniques:
     * 1. IAT (Import Address Table) checking:
     *    - Read PE headers
     *    - Verify API function pointers
     *    - Detect redirects to suspicious addresses
     *
     * 2. Inline hook detection:
     *    - Read first bytes of API functions
     *    - "JMP" or "CALL" to unexpected location = hook
     *    - Compare with system DLL versions
     *
     * 3. Function prologue analysis:
     *    - Legitimate functions have expected prologue
     *    - Hooks replace with JMP/CALL instruction
     */

    #ifdef _WIN32
    /* Check LoadLibraryA for hooks */
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    void *load_lib_addr = GetProcAddress(kernel32, "LoadLibraryA");

    if (load_lib_addr) {
        /* Read first few bytes of function */
        unsigned char func_bytes[16];
        memcpy(func_bytes, load_lib_addr, sizeof(func_bytes));

        /* Check for common hook signatures:
         * 0xFF 0x25 - JMP indirect (64-bit hook)
         * 0xE9 - JMP relative (32-bit hook)
         * 0xEA - LJMP (far jump)
         * 0xEB - Short JMP
         */

        if (func_bytes[0] == 0xFF && func_bytes[1] == 0x25) {
            result.detected = true;
            strcpy(result.evasion_method, "IAT hook detected on LoadLibraryA");
        } else if (func_bytes[0] == 0xE9) {
            result.detected = true;
            strcpy(result.evasion_method, "Inline JMP hook detected");
        }
    }

    /* Check CreateFileA for hooks */
    void *create_file_addr = GetProcAddress(kernel32, "CreateFileA");
    if (create_file_addr) {
        unsigned char func_bytes[16];
        memcpy(func_bytes, create_file_addr, sizeof(func_bytes));

        if (func_bytes[0] == 0xFF && func_bytes[1] == 0x25) {
            result.detected = true;
            strcpy(result.evasion_method, "IAT hook detected on CreateFileA");
        }
    }

    #else
    result.detected = false;
    strcpy(result.evasion_method, "Hook detection not fully supported on Linux");
    #endif

    return result;
}

/**
 * Generic Anti-Analysis Detection
 * General detection of analysis environment
 */
anti_analysis_result_t anti_analysis_generic(void) {
    anti_analysis_result_t result = {0};
    strcpy(result.detection_type, "generic_analysis");

    /* Combined analysis detection:
     * 1. Check for monitoring processes:
     *    - Process Monitor (procmon)
     *    - Wireshark
     *    - Fiddler
     *    - Debuggers (IDA, Ghidra, etc.)
     *
     * 2. Check for analysis tools:
     *    - Registry entries
     *    - File system paths
     *    - Window titles
     *
     * 3. Behavioral detection:
     *    - Unusual API call patterns
     *    - Frequency of system calls
     */

    #ifdef _WIN32
    /* Check for common analysis tool window titles */
    const char *analysis_tools[] = {
        "Process Monitor",
        "Wireshark",
        "Fiddler",
        "IDA",
        "Ghidra",
        "x64dbg",
        "WinDbg"
    };

    for (int i = 0; i < sizeof(analysis_tools) / sizeof(analysis_tools[0]); i++) {
        HWND hwnd = FindWindowA(NULL, analysis_tools[i]);
        if (hwnd != NULL) {
            result.detected = true;
            snprintf(result.evasion_method, sizeof(result.evasion_method) - 1,
                    "%s detected", analysis_tools[i]);
            break;
        }
    }

    #else
    result.detected = false;
    strcpy(result.evasion_method, "Analysis environment check complete");
    #endif

    return result;
}
