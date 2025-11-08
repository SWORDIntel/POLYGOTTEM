/*
 * polyglot_extract.c - Polyglot Image Payload Extractor
 * ======================================================
 *
 * Extracts and decrypts payloads from polyglot image files.
 * Attributed to APT TeamTNT cryptomining campaigns.
 *
 * Technique discovered in:
 * - APT TeamTNT operations (2020-2024)
 * - APT-41 KEYPLUG malware (2019-2024)
 *
 * For security research and VX Underground publication.
 *
 * Author: SWORDIntel
 * Date: 2025-11-08
 * Attribution: APT TeamTNT
 *
 * BUILD:
 *   gcc -O2 -Wall -o polyglot_extract polyglot_extract.c
 *
 * USAGE:
 *   ./polyglot_extract <polyglot_image> <output> [xor_key]
 *
 * EXAMPLE:
 *   ./polyglot_extract infected.gif payload.bin 9e0a61200d
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define VERSION "1.0.0"
#define MAX_FILE_SIZE (100 * 1024 * 1024)
#define DEFAULT_XOR_KEY "9e0a61200d"

// Image format EOF markers
typedef struct {
    const char *ext;
    const uint8_t *marker;
    size_t marker_len;
    const char *description;
} ImageFormat;

static const uint8_t GIF_HEADER[] = {0x47, 0x49, 0x46, 0x38};  // "GIF8"
static const uint8_t JPEG_HEADER[] = {0xff, 0xd8, 0xff};       // JPEG SOI
static const uint8_t PNG_HEADER[] = {0x89, 0x50, 0x4e, 0x47};  // "\x89PNG"

static const uint8_t GIF_EOF[] = {0x3b};
static const uint8_t JPEG_EOF[] = {0xff, 0xd9};
static const uint8_t PNG_EOF[] = {0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82};

static const ImageFormat FORMATS[] = {
    {"GIF",  GIF_EOF,  sizeof(GIF_EOF),  "GIF87a/89a"},
    {"JPEG", JPEG_EOF, sizeof(JPEG_EOF), "JPEG/JFIF"},
    {"PNG",  PNG_EOF,  sizeof(PNG_EOF),  "PNG"},
    {NULL, NULL, 0, NULL}
};

/*
 * Detect image format from header bytes
 */
const ImageFormat* detect_format_from_data(const uint8_t *data, size_t len) {
    if (len < 8) return NULL;

    if (memcmp(data, GIF_HEADER, sizeof(GIF_HEADER)) == 0) {
        return &FORMATS[0];  // GIF
    } else if (memcmp(data, JPEG_HEADER, sizeof(JPEG_HEADER)) == 0) {
        return &FORMATS[1];  // JPEG
    } else if (memcmp(data, PNG_HEADER, sizeof(PNG_HEADER)) == 0) {
        return &FORMATS[2];  // PNG
    }

    return NULL;
}

/*
 * Find last occurrence of EOF marker
 */
ssize_t find_eof_marker(const uint8_t *data, size_t data_len, const ImageFormat *fmt) {
    if (!data || !fmt || data_len < fmt->marker_len) {
        return -1;
    }

    for (ssize_t i = data_len - fmt->marker_len; i >= 0; i--) {
        if (memcmp(data + i, fmt->marker, fmt->marker_len) == 0) {
            return i + fmt->marker_len;
        }
    }

    return -1;
}

/*
 * Convert hex string to bytes
 */
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) {
        return -1;
    }

    size_t byte_len = hex_len / 2;
    for (size_t i = 0; i < byte_len; i++) {
        if (sscanf(hex + 2*i, "%2hhx", &bytes[i]) != 1) {
            return -1;
        }
    }

    return byte_len;
}

/*
 * XOR decrypt data
 */
void xor_decrypt(uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

/*
 * Detect payload type from decrypted data
 */
const char* detect_payload_type(const uint8_t *data, size_t len) {
    if (len < 4) return "Unknown (too small)";

    // ELF binary
    if (len >= 4 && memcmp(data, "\x7f""ELF", 4) == 0) {
        return "ELF binary (Linux executable)";
    }

    // PE binary
    if (len >= 2 && data[0] == 'M' && data[1] == 'Z') {
        return "PE binary (Windows executable)";
    }

    // Shell script
    if (len >= 2 && data[0] == '#' && data[1] == '!') {
        return "Shell script";
    }

    // ZIP archive
    if (len >= 4 && memcmp(data, "PK\x03\x04", 4) == 0) {
        return "ZIP archive";
    }

    // Check if mostly printable (script/text)
    size_t printable = 0;
    size_t check_len = (len < 1024) ? len : 1024;
    for (size_t i = 0; i < check_len; i++) {
        if ((data[i] >= 32 && data[i] <= 126) || data[i] == '\n' || data[i] == '\t') {
            printable++;
        }
    }

    if ((float)printable / check_len > 0.8) {
        return "Text/script file";
    }

    return "Binary data (unknown type)";
}

/*
 * Read entire file
 */
uint8_t* read_file(const char *filename, size_t *out_len) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        return NULL;
    }

    struct stat st;
    if (fstat(fileno(fp), &st) != 0) {
        perror("fstat");
        fclose(fp);
        return NULL;
    }

    size_t file_size = st.st_size;
    if (file_size == 0 || file_size > MAX_FILE_SIZE) {
        fprintf(stderr, "Invalid file size: %zu bytes\n", file_size);
        fclose(fp);
        return NULL;
    }

    uint8_t *data = malloc(file_size);
    if (!data) {
        perror("malloc");
        fclose(fp);
        return NULL;
    }

    size_t read_len = fread(data, 1, file_size, fp);
    fclose(fp);

    if (read_len != file_size) {
        fprintf(stderr, "Read error\n");
        free(data);
        return NULL;
    }

    *out_len = file_size;
    return data;
}

/*
 * Write data to file
 */
int write_file(const char *filename, const uint8_t *data, size_t data_len) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    size_t written = fwrite(data, 1, data_len, fp);
    fclose(fp);

    if (written != data_len) {
        fprintf(stderr, "Write error\n");
        return -1;
    }

    return 0;
}

/*
 * Main extraction function
 */
int extract_payload(const char *image_path, const char *output_path,
                    const char *xor_key_hex) {

    printf("[*] APT TeamTNT Polyglot Extractor v%s\n", VERSION);
    printf("[*] Polyglot image: %s\n", image_path);
    printf("[*] Output: %s\n", output_path);

    // Read polyglot file
    size_t file_len;
    uint8_t *file_data = read_file(image_path, &file_len);
    if (!file_data) {
        return 1;
    }
    printf("[*] File size: %zu bytes\n", file_len);

    // Detect format
    const ImageFormat *fmt = detect_format_from_data(file_data, file_len);
    if (!fmt) {
        fprintf(stderr, "[!] Cannot detect image format\n");
        free(file_data);
        return 1;
    }
    printf("[*] Detected format: %s (%s)\n", fmt->ext, fmt->description);

    // Find EOF marker
    ssize_t eof_pos = find_eof_marker(file_data, file_len, fmt);
    if (eof_pos < 0) {
        fprintf(stderr, "[!] EOF marker not found\n");
        free(file_data);
        return 1;
    }
    printf("[*] EOF marker at offset: 0x%zx (%zd bytes)\n", eof_pos, eof_pos);

    // Check for appended data
    if ((size_t)eof_pos >= file_len) {
        fprintf(stderr, "[!] No appended data found\n");
        free(file_data);
        return 1;
    }

    size_t payload_len = file_len - eof_pos;
    printf("[*] Appended data size: %zu bytes\n", payload_len);

    // Extract appended data
    uint8_t *encrypted_payload = malloc(payload_len);
    if (!encrypted_payload) {
        perror("malloc");
        free(file_data);
        return 1;
    }
    memcpy(encrypted_payload, file_data + eof_pos, payload_len);
    free(file_data);

    // Parse XOR key
    uint8_t xor_key[256];
    int key_len = hex_to_bytes(xor_key_hex, xor_key, sizeof(xor_key));
    if (key_len < 0) {
        fprintf(stderr, "[!] Invalid XOR key\n");
        free(encrypted_payload);
        return 1;
    }
    printf("[*] XOR key: %s (%d bytes)\n", xor_key_hex, key_len);

    // Decrypt
    printf("[*] Decrypting payload...\n");
    xor_decrypt(encrypted_payload, payload_len, xor_key, key_len);

    // Detect payload type
    const char *payload_type = detect_payload_type(encrypted_payload, payload_len);
    printf("[*] Payload type: %s\n", payload_type);

    // Write decrypted payload
    printf("[*] Writing decrypted payload...\n");
    if (write_file(output_path, encrypted_payload, payload_len) != 0) {
        free(encrypted_payload);
        return 1;
    }

    free(encrypted_payload);

    // Success
    printf("\n[+] Payload extracted successfully!\n");
    printf("    Polyglot file: %zu bytes\n", file_len);
    printf("    EOF position: %zd bytes\n", eof_pos);
    printf("    Encrypted size: %zu bytes\n", payload_len);
    printf("    Payload type: %s\n", payload_type);
    printf("    Output: %s\n", output_path);

    return 0;
}

/*
 * Usage information
 */
void usage(const char *progname) {
    printf("APT TeamTNT Polyglot Extractor v%s\n", VERSION);
    printf("\nUSAGE:\n");
    printf("  %s <polyglot_image> <output> [xor_key]\n\n", progname);
    printf("ARGUMENTS:\n");
    printf("  polyglot_image   Polyglot image file to extract from\n");
    printf("  output           Output file for decrypted payload\n");
    printf("  xor_key          XOR key in hex (default: %s)\n\n", DEFAULT_XOR_KEY);
    printf("EXAMPLES:\n");
    printf("  # Extract with default TeamTNT key\n");
    printf("  %s infected.gif payload.bin\n\n", progname);
    printf("  # Extract with custom key\n");
    printf("  %s stego.jpg malware.sh 9e0a61200d\n\n", progname);
    printf("  # Single-byte XOR\n");
    printf("  %s image.png script.sh d3\n\n", progname);
    printf("SUPPORTED FORMATS:\n");
    printf("  Automatically detects: GIF, JPEG, PNG\n\n");
    printf("PAYLOAD TYPES DETECTED:\n");
    printf("  - ELF binaries (Linux executables)\n");
    printf("  - PE binaries (Windows executables)\n");
    printf("  - Shell scripts (#!/bin/sh, etc)\n");
    printf("  - ZIP archives\n");
    printf("  - Text/script files\n");
    printf("  - Unknown binary data\n\n");
    printf("ATTRIBUTION:\n");
    printf("  Technique: APT TeamTNT cryptomining campaigns\n");
    printf("  Also seen: APT-41 KEYPLUG malware\n");
    printf("  Analysis: SWORDIntel (2025)\n\n");
    printf("For VX Underground publication and security research only.\n");
}

/*
 * Main entry point
 */
int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) {
        usage(argv[0]);
        return 1;
    }

    const char *image_path = argv[1];
    const char *output_path = argv[2];
    const char *xor_key = (argc == 4) ? argv[3] : DEFAULT_XOR_KEY;

    return extract_payload(image_path, output_path, xor_key);
}
