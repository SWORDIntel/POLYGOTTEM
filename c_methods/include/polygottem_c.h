/**
 * POLYGOTTEM C Methods Framework
 * ==============================
 *
 * Advanced C-based exploitation, utilities, and payload generation
 * for defensive security research and authorized testing.
 *
 * This header exports all C methods from the POLYGOTTEM framework.
 */

#ifndef POLYGOTTEM_C_H
#define POLYGOTTEM_C_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * CATEGORY 1: C-BASED EXPLOITATION METHODS
 * ============================================================ */

/* Privilege Escalation Methods */
typedef struct {
    uint32_t pid;
    uint32_t target_pid;
    char capability[64];
    bool success;
} priv_esc_result_t;

priv_esc_result_t pe_kernel_race_condition(uint32_t target_pid);
priv_esc_result_t pe_capability_abuse(uint32_t target_pid, const char *capability);
priv_esc_result_t pe_selinux_bypass(const char *context, const char *target);
priv_esc_result_t pe_token_impersonation(uint32_t target_token);
priv_esc_result_t pe_com_hijacking(const char *com_object);

/* Memory Exploitation Methods */
typedef struct {
    uint64_t target_address;
    size_t overflow_size;
    uint8_t *payload;
    size_t payload_size;
    bool success;
} mem_exploit_result_t;

mem_exploit_result_t mem_buffer_overflow(uint64_t target_addr, const uint8_t *payload, size_t size);
mem_exploit_result_t mem_use_after_free(uint64_t target_addr, const uint8_t *payload, size_t size);
mem_exploit_result_t mem_heap_corruption(uint64_t target_addr, size_t corruption_size);
mem_exploit_result_t mem_stack_pivot(uint64_t stack_base, uint64_t target_gadget);

/* Kernel Exploitation Methods */
typedef struct {
    uint32_t syscall_id;
    const char *method_name;
    bool success;
    char error_msg[256];
} kernel_exploit_result_t;

kernel_exploit_result_t kernel_module_loader(const char *module_path);
kernel_exploit_result_t kernel_syscall_fuzzer(uint32_t syscall_range_start, uint32_t syscall_range_end);
kernel_exploit_result_t kernel_direct_access(uint64_t target_addr);
kernel_exploit_result_t kernel_alpc_exploitation(const char *port_name);

/* Windows-Specific Methods */
typedef struct {
    uint32_t result_code;
    void *handle;
    bool elevated;
} windows_exploit_result_t;

windows_exploit_result_t win_token_impersonate(const char *username);
windows_exploit_result_t win_com_hijack(const char *com_clsid);
windows_exploit_result_t win_alpc_exploit(const char *port_name);
windows_exploit_result_t win_gdi_exploit(void);

/* ============================================================
 * CATEGORY 2: ADVANCED C UTILITIES (EXECUTION METHODS)
 * ============================================================ */

/* Process Injection Methods */
typedef struct {
    uint32_t source_pid;
    uint32_t target_pid;
    uint64_t injection_address;
    bool success;
} injection_result_t;

injection_result_t inj_dll_injection(uint32_t target_pid, const char *dll_path);
injection_result_t inj_shellcode_execution(uint32_t target_pid, const uint8_t *shellcode, size_t size);
injection_result_t inj_remote_code_execution(uint32_t target_pid, void *function_ptr, void *args);
injection_result_t inj_process_hollowing(const char *executable_path, const uint8_t *payload, size_t size);

/* System Manipulation Methods */
typedef struct {
    const char *operation;
    bool success;
    char result[512];
} sys_manip_result_t;

sys_manip_result_t sys_file_operations(const char *operation, const char *source, const char *dest);
sys_manip_result_t sys_registry_manipulation(const char *hive, const char *key, const char *value);
sys_manip_result_t sys_network_hijacking(const char *target_ip, uint16_t target_port);
sys_manip_result_t sys_environment_modify(const char *var_name, const char *var_value);

/* Anti-Analysis Methods */
typedef struct {
    const char *detection_type;
    bool detected;
    const char *evasion_method;
} anti_analysis_result_t;

anti_analysis_result_t anti_vm_detection(void);
anti_analysis_result_t anti_debugger_detection(void);
anti_analysis_result_t anti_hook_detection(void);
anti_analysis_result_t anti_analysis_generic(void);

/* Obfuscation Methods */
typedef struct {
    uint8_t *obfuscated_data;
    size_t obfuscated_size;
    uint32_t obfuscation_key;
} obfuscation_result_t;

obfuscation_result_t obf_code_obfuscation(const uint8_t *code, size_t code_size);
obfuscation_result_t obf_string_encryption(const char *plaintext);
obfuscation_result_t obf_control_flow_flattening(const uint8_t *code, size_t code_size);
obfuscation_result_t obf_polymorphic_engine(const uint8_t *payload, size_t payload_size);

/* ============================================================
 * CATEGORY 3: NATIVE C COMPONENTS (PERFORMANCE-CRITICAL)
 * ============================================================ */

/* Cryptography Methods */
typedef struct {
    uint8_t *output;
    size_t output_size;
    uint8_t iv[16];
    uint8_t key[32];
} crypto_result_t;

crypto_result_t crypto_aes_encrypt(const uint8_t *plaintext, size_t plaintext_size, const uint8_t *key, const uint8_t *iv);
crypto_result_t crypto_aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_size, const uint8_t *key, const uint8_t *iv);
crypto_result_t crypto_xor_operation(const uint8_t *data, size_t data_size, uint32_t key);
void crypto_sha256(const uint8_t *data, size_t data_size, uint8_t *hash_output);
void crypto_md5(const uint8_t *data, size_t data_size, uint8_t *hash_output);

/* Memory Operations */
typedef struct {
    uint64_t found_address;
    size_t found_size;
    bool success;
} memory_ops_result_t;

memory_ops_result_t mem_scan_pattern(const uint8_t *pattern, size_t pattern_size, uint64_t search_start, uint64_t search_end);
memory_ops_result_t mem_pattern_matching(const uint8_t *data, size_t data_size, const uint8_t *pattern, size_t pattern_size);
void mem_fast_copy(void *dest, const void *src, size_t size);
void mem_secure_zero(void *ptr, size_t size);

/* Network Operations */
typedef struct {
    int socket_fd;
    char remote_addr[256];
    uint16_t remote_port;
    bool connected;
} network_ops_result_t;

network_ops_result_t net_raw_socket(int socket_type);
network_ops_result_t net_packet_crafting(const uint8_t *packet_data, size_t packet_size);
network_ops_result_t net_protocol_implementation(const char *protocol_name);
int net_send_packet(int socket_fd, const uint8_t *packet, size_t packet_size);

/* Compression Methods */
typedef struct {
    uint8_t *compressed_data;
    size_t compressed_size;
} compression_result_t;

compression_result_t compress_payload(const uint8_t *payload, size_t payload_size, int compression_level);
uint8_t *decompress_payload(const uint8_t *compressed, size_t compressed_size, size_t *decompressed_size);
compression_result_t compress_lz4(const uint8_t *payload, size_t payload_size);
compression_result_t compress_zstd(const uint8_t *payload, size_t payload_size);

/* ============================================================
 * CATEGORY 4: CROSS-PLATFORM C PAYLOADS
 * ============================================================ */

/* Windows Payloads */
typedef struct {
    const char *payload_type;
    uint8_t *payload_data;
    size_t payload_size;
} payload_result_t;

payload_result_t payload_win32_api(const char *api_name, void **args);
payload_result_t payload_wmi_execution(const char *command);
payload_result_t payload_scheduled_task(const char *task_name, const char *command);
payload_result_t payload_registry_rce(const char *registry_path);

/* Linux Payloads */
payload_result_t payload_ptrace_exploit(uint32_t target_pid);
payload_result_t payload_ld_preload_hijack(const char *library_path);
payload_result_t payload_cgroup_escape(void);
payload_result_t payload_namespace_escape(void);

/* macOS Payloads */
payload_result_t payload_dyld_hijacking(const char *dylib_path);
payload_result_t payload_sandbox_escape(void);
payload_result_t payload_kernel_pac_bypass(void);
payload_result_t payload_xpc_hijacking(const char *service_name);

/* ============================================================
 * UTILITY FUNCTIONS
 * ============================================================ */

/* Memory allocation and cleanup */
void *polygottem_malloc(size_t size);
void polygottem_free(void *ptr);
void polygottem_free_result(void *result_ptr);

/* Initialization and cleanup */
int polygottem_c_init(void);
void polygottem_c_cleanup(void);

/* Get version and metadata */
const char *polygottem_c_version(void);
const char *polygottem_c_platform(void);

#ifdef __cplusplus
}
#endif

#endif /* POLYGOTTEM_C_H */
