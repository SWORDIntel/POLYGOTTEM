/**
 * Obfuscation Methods
 * ====================
 *
 * Category 2: Advanced C Utilities
 * Implements code obfuscation, string encryption, and control flow flattening
 *
 * DEFENSIVE RESEARCH ONLY - AUTHORIZED USE REQUIRED
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "polygottem_c.h"

/**
 * Code Obfuscation
 * Obfuscates binary code to prevent reverse engineering
 */
obfuscation_result_t obf_code_obfuscation(const uint8_t *code, size_t code_size) {
    obfuscation_result_t result = {0};

    if (!code || code_size == 0) {
        return result;
    }

    /* Code obfuscation techniques:
     * 1. Junk code injection:
     *    - Insert NOP sleds
     *    - Add unreachable code paths
     *    - Include dummy calculations
     *
     * 2. Dead code elimination:
     *    - Remove unused variables/functions
     *    - Compress code sections
     *
     * 3. Control flow obfuscation:
     *    - Replace simple jumps with conditional branches
     *    - Add unnecessary loops
     *    - Flatten control flow (see control_flow_flattening)
     *
     * 4. Register allocation obfuscation:
     *    - Use non-optimal register usage
     *    - Force unnecessary memory accesses
     *    - Spill/reload registers excessively
     */

    /* Allocate output buffer */
    result.obfuscated_data = (uint8_t *)malloc(code_size * 2);
    if (!result.obfuscated_data) {
        return result;
    }

    /* Simple XOR-based obfuscation with junk code */
    uint8_t *output = result.obfuscated_data;
    size_t output_pos = 0;

    for (size_t i = 0; i < code_size; i++) {
        /* Original code byte with XOR key */
        uint8_t key = 0xAA;
        output[output_pos++] = code[i] ^ key;

        /* Every 4 bytes, inject junk instructions */
        if ((i % 4) == 3) {
            /* NOP sled (0x90 on x86) */
            output[output_pos++] = 0x90;
            output[output_pos++] = 0x90;
        }
    }

    result.obfuscated_size = output_pos;
    result.obfuscation_key = 0xAA;

    return result;
}

/**
 * String Encryption
 * Encrypts strings to hide them from static analysis
 */
obfuscation_result_t obf_string_encryption(const char *plaintext) {
    obfuscation_result_t result = {0};

    if (!plaintext) {
        return result;
    }

    /* String encryption methodology:
     * 1. Identify sensitive strings:
     *    - API names (LoadLibraryA, CreateProcessA, etc.)
     *    - Registry paths
     *    - File paths
     *    - Command line arguments
     *    - C2 server addresses
     *
     * 2. Encryption methods:
     *    - XOR with single/multi-byte key
     *    - AES encryption
     *    - Custom encryption routines
     *    - Base64 encoding + XOR
     *
     * 3. Decryption at runtime:
     *    - Just-in-time decryption before use
     *    - Immediate re-encryption after use
     *    - Prevent string table dumps
     */

    size_t plaintext_len = strlen(plaintext);
    result.obfuscated_data = (uint8_t *)malloc(plaintext_len + 1);

    if (result.obfuscated_data) {
        uint8_t xor_key = 0x42;
        result.obfuscation_key = xor_key;

        /* XOR encryption */
        for (size_t i = 0; i < plaintext_len; i++) {
            result.obfuscated_data[i] = plaintext[i] ^ xor_key;
        }
        result.obfuscated_data[plaintext_len] = 0;  /* Null terminator */

        result.obfuscated_size = plaintext_len;
    }

    return result;
}

/**
 * Control Flow Flattening
 * Transforms control flow to prevent analysis
 */
obfuscation_result_t obf_control_flow_flattening(const uint8_t *code, size_t code_size) {
    obfuscation_result_t result = {0};

    if (!code || code_size == 0) {
        return result;
    }

    /* Control flow flattening methodology:
     * 1. Identify all basic blocks in code
     * 2. Create state machine:
     *    - Assign each block a unique state ID
     *    - Use variable to track current state
     *    - Switch on state variable to dispatch
     *
     * 3. Example transformation:
     *    Original:
     *    if (condition) { block_a(); } else { block_b(); }
     *
     *    Flattened:
     *    state = condition ? STATE_A : STATE_B;
     *    while (state != END) {
     *        switch (state) {
     *            case STATE_A: block_a(); state = END; break;
     *            case STATE_B: block_b(); state = END; break;
     *        }
     *    }
     *
     * 4. Benefits for adversary:
     *    - Prevents jump prediction
     *    - Makes symbolic execution harder
     *    - Complicates decompilation
     */

    /* Allocate space for flattened code */
    size_t flattened_size = code_size + (code_size / 8) + 100;  /* Overhead for state machine */
    result.obfuscated_data = (uint8_t *)malloc(flattened_size);

    if (result.obfuscated_data) {
        uint8_t *output = result.obfuscated_data;

        /* Build state machine switch statement */
        memcpy(output, code, code_size);

        /* Add switch dispatcher at end
         * In real implementation:
         * 1. Analyze control flow
         * 2. Identify jump targets
         * 3. Assign state IDs
         * 4. Insert switch statement
         */

        result.obfuscated_size = code_size + 32;  /* Simplified size */
        result.obfuscation_key = 0xFF;
    }

    return result;
}

/**
 * Polymorphic Engine
 * Generates morphing code that changes on each execution
 */
obfuscation_result_t obf_polymorphic_engine(const uint8_t *payload, size_t payload_size) {
    obfuscation_result_t result = {0};

    if (!payload || payload_size == 0) {
        return result;
    }

    /* Polymorphic engine methodology:
     * 1. Core engine:
     *    - Decrypt stub stays same (encryption key changes)
     *    - Encrypted payload changes each execution
     *    - Decryption routines vary
     *
     * 2. Mutation techniques:
     *    - Random encryption key generation
     *    - Randomly chosen decryption algorithm
     *    - Variable junk code insertion
     *    - Register usage randomization
     *    - Instruction sequence variation
     *
     * 3. Benefits for adversary:
     *    - Defeats signature-based detection
     *    - Evades YARA rules with fixed patterns
     *    - Different hash each generation
     *    - Complicates malware analysis
     *
     * 4. Common mutators:
     *    - Substitution: Replace instruction with equivalent
     *    - Permutation: Reorder non-dependent instructions
     *    - Injection: Add junk code
     *    - Transposition: Swap register usage patterns
     */

    /* Generate random encryption key */
    uint32_t random_key = 0xDEADBEEF ^ ((uint32_t)payload ^ payload_size);

    result.obfuscated_data = (uint8_t *)malloc(payload_size + 256);

    if (result.obfuscated_data) {
        uint8_t *output = result.obfuscated_data;
        size_t output_pos = 0;

        /* Generate polymorphic decryptor stub
         * This stub varies each time but accomplishes same goal
         */

        /* Example: Generate variable-length NOP sled */
        uint8_t sled_length = (random_key >> 16) & 0x1F;
        for (int i = 0; i < sled_length; i++) {
            output[output_pos++] = 0x90;  /* NOP */
        }

        /* Encrypt payload with random key */
        for (size_t i = 0; i < payload_size; i++) {
            output[output_pos++] = payload[i] ^ (random_key + i);
        }

        result.obfuscated_size = output_pos;
        result.obfuscation_key = random_key;
    }

    return result;
}
