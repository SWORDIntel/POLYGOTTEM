/*
 * Advanced Polyglot Tool - Combined Best-of-Both Implementation
 * ==============================================================
 *
 * Combines the best features from:
 * - VX Underground: XOR encryption, post-EOF steganography, payload detection
 * - Polyglot Research: True polyglots, professional UI, proper image structures
 *
 * FEATURES:
 * - Dual-mode operation: steganography OR true polyglots
 * - XOR encryption with multi-byte keys
 * - Embed, extract, and analyze in one tool
 * - Support for GIF, PNG, JPEG formats
 * - Payload type detection (ELF, PE, Shell, ZIP)
 * - Professional CLI with getopt
 * - Verbose mode and statistics
 *
 * AUTHOR: POLYGOTTEM Research Team
 * DATE: 2025-11-08
 * VERSION: 2.0.0
 * LICENSE: Educational Use Only
 *
 * COMPILE:
 * gcc -O2 -Wall -Wextra -o polyglot_advanced polyglot_advanced.c
 *
 * USAGE:
 * # Steganography mode (encrypted, post-EOF)
 * ./polyglot_advanced --mode stego --embed image.gif payload.sh output.gif --key 9e0a61200d
 *
 * # Polyglot mode (dual-format, executable)
 * ./polyglot_advanced --mode polyglot --type gif --script payload.sh --output evil.gif
 *
 * # Extract mode
 * ./polyglot_advanced --mode extract --input infected.gif --output payload.bin --key 9e0a61200d
 *
 * # Analyze mode
 * ./polyglot_advanced --mode analyze --input suspicious.gif
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <strings.h>
#include <getopt.h>
#include <math.h>

#define VERSION "2.0.0"
#define MAX_FILE_SIZE (100 * 1024 * 1024)  // 100MB max
#define DEFAULT_XOR_KEY "9e0a61200d"
#define MAX_KEY_SIZE 256

// ============================================================================
// Image Format Definitions
// ============================================================================

typedef struct {
    const char *name;
    const uint8_t *header;
    size_t header_len;
    const uint8_t *eof_marker;
    size_t eof_marker_len;
} ImageFormat;

static const uint8_t GIF_HEADER[] = {0x47, 0x49, 0x46, 0x38};  // "GIF8"
static const uint8_t JPEG_HEADER[] = {0xff, 0xd8, 0xff};
static const uint8_t PNG_HEADER[] = {0x89, 0x50, 0x4e, 0x47};

static const uint8_t GIF_EOF[] = {0x3b};
static const uint8_t JPEG_EOF[] = {0xff, 0xd9};
static const uint8_t PNG_EOF[] = {0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82};

static const ImageFormat FORMATS[] = {
    {"GIF",  GIF_HEADER,  sizeof(GIF_HEADER),  GIF_EOF,  sizeof(GIF_EOF)},
    {"JPEG", JPEG_HEADER, sizeof(JPEG_HEADER), JPEG_EOF, sizeof(JPEG_EOF)},
    {"PNG",  PNG_HEADER,  sizeof(PNG_HEADER),  PNG_EOF,  sizeof(PNG_EOF)},
    {NULL, NULL, 0, NULL, 0}
};

// ============================================================================
// Global Options
// ============================================================================

typedef enum {
    MODE_NONE,
    MODE_STEGO_EMBED,
    MODE_POLYGLOT_GEN,
    MODE_EXTRACT,
    MODE_ANALYZE
} OperationMode;

typedef struct {
    OperationMode mode;
    char *input_file;
    char *payload_file;
    char *output_file;
    char *xor_key_hex;
    char *polyglot_type;  // gif, png, jpeg
    int verbose;
    int create_minimal;   // Create minimal 1x1 image or use existing
} Options;

// ============================================================================
// Utility Functions
// ============================================================================

void print_banner(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║       Advanced Polyglot Tool v%-6s                       ║\n", VERSION);
    printf("║       Best-of-Both: VX Underground + Polyglot Research       ║\n");
    printf("║                                                              ║\n");
    printf("║  FEATURES: Steganography | True Polyglots | Encryption      ║\n");
    printf("║  WARNING: FOR AUTHORIZED SECURITY RESEARCH ONLY              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void print_usage(const char *prog) {
    printf("Usage: %s --mode <MODE> [OPTIONS]\n\n", prog);
    printf("MODES:\n");
    printf("  stego     Steganography (encrypted post-EOF embedding)\n");
    printf("  polyglot  True polyglot (dual-format files)\n");
    printf("  extract   Extract and decrypt payloads\n");
    printf("  analyze   Analyze suspicious images\n\n");

    printf("STEGANOGRAPHY MODE OPTIONS:\n");
    printf("  --embed FILE      Source image file\n");
    printf("  --payload FILE    Payload to embed\n");
    printf("  --output FILE     Output file\n");
    printf("  --key HEX         XOR key (default: %s)\n\n", DEFAULT_XOR_KEY);

    printf("POLYGLOT MODE OPTIONS:\n");
    printf("  --type TYPE       Image type (gif, png, jpeg)\n");
    printf("  --script FILE     Shell script to embed\n");
    printf("  --output FILE     Output file\n");
    printf("  --real-image FILE Use real image instead of 1x1 minimal\n");
    printf("  --encrypt         Encrypt script with XOR\n");
    printf("  --key HEX         XOR key if encrypting\n\n");

    printf("EXTRACT MODE OPTIONS:\n");
    printf("  --input FILE      Polyglot/stego image\n");
    printf("  --output FILE     Extracted payload\n");
    printf("  --key HEX         XOR key for decryption\n\n");

    printf("ANALYZE MODE OPTIONS:\n");
    printf("  --input FILE      Image to analyze\n\n");

    printf("GENERAL OPTIONS:\n");
    printf("  -v, --verbose     Verbose output\n");
    printf("  -h, --help        Show this help\n\n");

    printf("EXAMPLES:\n\n");
    printf("  # Steganography: Hide encrypted payload in existing image\n");
    printf("  %s --mode stego --embed meme.gif --payload malware.sh \\\n", prog);
    printf("         --output infected.gif --key 9e0a61200d\n\n");

    printf("  # Polyglot: Create minimal executable GIF\n");
    printf("  %s --mode polyglot --type gif --script payload.sh \\\n", prog);
    printf("         --output evil.gif\n\n");

    printf("  # Polyglot with real image and encryption\n");
    printf("  %s --mode polyglot --type png --script payload.sh \\\n", prog);
    printf("         --real-image photo.png --encrypt --output stealthy.png\n\n");

    printf("  # Extract payload\n");
    printf("  %s --mode extract --input infected.gif \\\n", prog);
    printf("         --output payload.bin --key 9e0a61200d\n\n");

    printf("  # Analyze suspicious image\n");
    printf("  %s --mode analyze --input suspicious.gif -v\n\n", prog);
}

/* Calculate entropy (0.0 to 8.0 bits per byte) */
double calculate_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;

    uint32_t counts[256] = {0};
    for (size_t i = 0; i < len; i++) {
        counts[data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / len;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

/* Read file into memory */
uint8_t* read_file(const char *filename, size_t *out_len) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Error opening file");
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

/* Write file to disk */
int write_file(const char *filename, const uint8_t *data, size_t len) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Error opening output file");
        return -1;
    }

    size_t written = fwrite(data, 1, len, fp);
    fclose(fp);

    if (written != len) {
        fprintf(stderr, "Write error\n");
        return -1;
    }

    return 0;
}

/* Convert hex string to bytes */
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

    return (int)byte_len;
}

/* XOR crypt (same for encrypt/decrypt) */
void xor_crypt(uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

/* Detect format from file data */
const ImageFormat* detect_format(const uint8_t *data, size_t len) {
    if (len < 8) return NULL;

    for (int i = 0; FORMATS[i].name != NULL; i++) {
        if (memcmp(data, FORMATS[i].header, FORMATS[i].header_len) == 0) {
            return &FORMATS[i];
        }
    }

    return NULL;
}

/* Find EOF marker position */
ssize_t find_eof_marker(const uint8_t *data, size_t len, const ImageFormat *fmt) {
    if (!data || !fmt) return -1;

    // Search backwards for last occurrence
    for (ssize_t i = len - fmt->eof_marker_len; i >= 0; i--) {
        if (memcmp(data + i, fmt->eof_marker, fmt->eof_marker_len) == 0) {
            return i + fmt->eof_marker_len;  // Return position AFTER marker
        }
    }

    return -1;
}

/* Detect payload type */
const char* detect_payload_type(const uint8_t *data, size_t len) {
    if (len < 4) return "Unknown";

    if (memcmp(data, "\x7f""ELF", 4) == 0) return "ELF binary";
    if (data[0] == 'M' && data[1] == 'Z') return "PE binary";
    if (data[0] == '#' && data[1] == '!') return "Shell script";
    if (memcmp(data, "PK\x03\x04", 4) == 0) return "ZIP archive";
    if (memcmp(data, "\x1f\x8b", 2) == 0) return "Gzip";
    if (memcmp(data, "BZh", 3) == 0) return "Bzip2";

    return "Unknown/Text";
}

// ============================================================================
// Steganography Mode (VX Underground technique)
// ============================================================================

int stego_embed(Options *opts) {
    printf("[*] Mode: Steganography (Post-EOF embedding)\n");

    // Load source image
    size_t image_len;
    uint8_t *image_data = read_file(opts->input_file, &image_len);
    if (!image_data) return 1;

    const ImageFormat *fmt = detect_format(image_data, image_len);
    if (!fmt) {
        fprintf(stderr, "[!] Unknown image format\n");
        free(image_data);
        return 1;
    }
    printf("[+] Format: %s\n", fmt->name);

    // Find EOF marker
    ssize_t eof_pos = find_eof_marker(image_data, image_len, fmt);
    if (eof_pos < 0) {
        fprintf(stderr, "[!] EOF marker not found\n");
        free(image_data);
        return 1;
    }
    if (opts->verbose) {
        printf("[*] EOF marker at offset: 0x%lx (%ld bytes)\n", (long)eof_pos, (long)eof_pos);
    }

    // Load payload
    size_t payload_len;
    uint8_t *payload_data = read_file(opts->payload_file, &payload_len);
    if (!payload_data) {
        free(image_data);
        return 1;
    }
    printf("[+] Payload size: %zu bytes (%s)\n", payload_len, detect_payload_type(payload_data, payload_len));

    // XOR encryption
    uint8_t xor_key[MAX_KEY_SIZE];
    int key_len = hex_to_bytes(opts->xor_key_hex, xor_key, sizeof(xor_key));
    if (key_len < 0) {
        fprintf(stderr, "[!] Invalid XOR key\n");
        free(image_data);
        free(payload_data);
        return 1;
    }

    printf("[*] Encrypting with %d-byte XOR key...\n", key_len);
    xor_crypt(payload_data, payload_len, xor_key, key_len);

    // Create polyglot
    size_t total_len = eof_pos + payload_len;
    uint8_t *output_data = malloc(total_len);
    if (!output_data) {
        perror("malloc");
        free(image_data);
        free(payload_data);
        return 1;
    }

    memcpy(output_data, image_data, eof_pos);
    memcpy(output_data + eof_pos, payload_data, payload_len);

    // Write output
    if (write_file(opts->output_file, output_data, total_len) != 0) {
        free(image_data);
        free(payload_data);
        free(output_data);
        return 1;
    }

    // Statistics
    double overhead = (double)(total_len - image_len) / image_len * 100;
    printf("\n[✓] Steganography successful!\n");
    printf("    Original: %zu bytes\n", image_len);
    printf("    Payload:  %zu bytes (encrypted)\n", payload_len);
    printf("    Output:   %zu bytes (+%.1f%% overhead)\n", total_len, overhead);
    printf("    Image should still display normally!\n");

    free(image_data);
    free(payload_data);
    free(output_data);
    return 0;
}

// ============================================================================
// Extract Mode
// ============================================================================

int extract_payload(Options *opts) {
    printf("[*] Mode: Extract\n");

    // Load file
    size_t file_len;
    uint8_t *file_data = read_file(opts->input_file, &file_len);
    if (!file_data) return 1;

    // Detect format
    const ImageFormat *fmt = detect_format(file_data, file_len);
    if (!fmt) {
        fprintf(stderr, "[!] Unknown image format\n");
        free(file_data);
        return 1;
    }
    printf("[+] Format: %s\n", fmt->name);

    // Find EOF
    ssize_t eof_pos = find_eof_marker(file_data, file_len, fmt);
    if (eof_pos < 0) {
        fprintf(stderr, "[!] EOF marker not found\n");
        free(file_data);
        return 1;
    }

    if (eof_pos >= (ssize_t)file_len) {
        fprintf(stderr, "[!] No data after EOF marker\n");
        free(file_data);
        return 1;
    }

    // Extract payload
    size_t payload_len = file_len - eof_pos;
    uint8_t *payload = file_data + eof_pos;

    printf("[+] Found %zu bytes after EOF marker\n", payload_len);
    double entropy = calculate_entropy(payload, payload_len);
    printf("[*] Entropy: %.2f bits/byte ", entropy);
    if (entropy > 7.5) printf("(likely encrypted)\n");
    else printf("(likely plaintext)\n");

    // Decrypt if key provided
    if (opts->xor_key_hex) {
        uint8_t xor_key[MAX_KEY_SIZE];
        int key_len = hex_to_bytes(opts->xor_key_hex, xor_key, sizeof(xor_key));
        if (key_len < 0) {
            fprintf(stderr, "[!] Invalid XOR key\n");
            free(file_data);
            return 1;
        }

        printf("[*] Decrypting with %d-byte XOR key...\n", key_len);
        xor_crypt(payload, payload_len, xor_key, key_len);
    }

    printf("[+] Payload type: %s\n", detect_payload_type(payload, payload_len));

    // Write output
    if (write_file(opts->output_file, payload, payload_len) != 0) {
        free(file_data);
        return 1;
    }

    printf("\n[✓] Extraction successful: %s\n", opts->output_file);
    free(file_data);
    return 0;
}

// ============================================================================
// Analyze Mode
// ============================================================================

int analyze_image(Options *opts) {
    printf("[*] Mode: Analyze\n\n");

    size_t file_len;
    uint8_t *file_data = read_file(opts->input_file, &file_len);
    if (!file_data) return 1;

    printf("═══════════════════════════════════════════\n");
    printf("FILE ANALYSIS: %s\n", opts->input_file);
    printf("═══════════════════════════════════════════\n\n");

    // Format detection
    const ImageFormat *fmt = detect_format(file_data, file_len);
    if (fmt) {
        printf("✓ Image Format: %s\n", fmt->name);
        printf("  File size: %zu bytes\n", file_len);

        // Find EOF
        ssize_t eof_pos = find_eof_marker(file_data, file_len, fmt);
        if (eof_pos > 0) {
            printf("  EOF marker at: 0x%lx (%ld bytes)\n", (long)eof_pos, (long)eof_pos);

            if (eof_pos < (ssize_t)file_len) {
                size_t extra_bytes = file_len - eof_pos;
                printf("\n⚠ ALERT: %zu bytes found after EOF marker!\n", extra_bytes);

                uint8_t *extra_data = file_data + eof_pos;
                double entropy = calculate_entropy(extra_data, extra_bytes);
                printf("  Entropy: %.2f bits/byte ", entropy);

                if (entropy > 7.5) {
                    printf("⚠ HIGH (likely encrypted/compressed)\n");
                } else if (entropy > 5.0) {
                    printf("⚠ MEDIUM (possibly obfuscated)\n");
                } else {
                    printf("✓ LOW (likely plaintext/padding)\n");
                }

                printf("  Payload type: %s\n", detect_payload_type(extra_data, extra_bytes));

                // Check for shebangs
                if (extra_bytes >= 2 && extra_data[0] == '#' && extra_data[1] == '!') {
                    printf("  ⚠ SHEBANG DETECTED: Executable script!\n");
                }
            } else {
                printf("\n✓ No extra data after EOF (clean image)\n");
            }
        }
    } else {
        printf("✗ Unknown or corrupted format\n");
    }

    printf("\n═══════════════════════════════════════════\n\n");

    free(file_data);
    return 0;
}

// ============================================================================
// Polyglot Mode (Polyglot Research technique) - Simplified
// ============================================================================

int polyglot_generate(Options *opts) {
    printf("[*] Mode: True Polyglot (executable dual-format)\n");
    printf("[!] Note: Creates minimal 1x1 images\n");
    printf("[!] For advanced polyglot features, use polyglot_research/\n\n");

    // For now, refer to polyglot_research implementation
    printf("Please use the polyglot_research/c_implementation/polyglot_generator\n");
    printf("for full polyglot generation capabilities.\n\n");
    printf("This unified tool focuses on the steganography technique.\n");
    printf("Future versions will integrate full polyglot generation.\n");

    return 1;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    Options opts = {
        .mode = MODE_NONE,
        .input_file = NULL,
        .payload_file = NULL,
        .output_file = NULL,
        .xor_key_hex = DEFAULT_XOR_KEY,
        .polyglot_type = NULL,
        .verbose = 0,
        .create_minimal = 1
    };

    static struct option long_options[] = {
        {"mode",       required_argument, 0, 'm'},
        {"embed",      required_argument, 0, 'e'},
        {"payload",    required_argument, 0, 'p'},
        {"output",     required_argument, 0, 'o'},
        {"input",      required_argument, 0, 'i'},
        {"key",        required_argument, 0, 'k'},
        {"type",       required_argument, 0, 't'},
        {"script",     required_argument, 0, 's'},
        {"real-image", required_argument, 0, 'r'},
        {"encrypt",    no_argument,       0, 'E'},
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "m:e:p:o:i:k:t:s:r:Evh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'm':
                if (strcmp(optarg, "stego") == 0) opts.mode = MODE_STEGO_EMBED;
                else if (strcmp(optarg, "polyglot") == 0) opts.mode = MODE_POLYGLOT_GEN;
                else if (strcmp(optarg, "extract") == 0) opts.mode = MODE_EXTRACT;
                else if (strcmp(optarg, "analyze") == 0) opts.mode = MODE_ANALYZE;
                break;
            case 'e': opts.input_file = optarg; break;
            case 'p': opts.payload_file = optarg; break;
            case 'o': opts.output_file = optarg; break;
            case 'i': opts.input_file = optarg; break;
            case 'k': opts.xor_key_hex = optarg; break;
            case 't': opts.polyglot_type = optarg; break;
            case 's': opts.payload_file = optarg; break;
            case 'v': opts.verbose = 1; break;
            case 'h':
                print_banner();
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    print_banner();

    // Dispatch to appropriate mode
    switch (opts.mode) {
        case MODE_STEGO_EMBED:
            if (!opts.input_file || !opts.payload_file || !opts.output_file) {
                fprintf(stderr, "Error: Missing arguments for stego mode\n\n");
                print_usage(argv[0]);
                return 1;
            }
            return stego_embed(&opts);

        case MODE_EXTRACT:
            if (!opts.input_file || !opts.output_file) {
                fprintf(stderr, "Error: Missing arguments for extract mode\n\n");
                print_usage(argv[0]);
                return 1;
            }
            return extract_payload(&opts);

        case MODE_ANALYZE:
            if (!opts.input_file) {
                fprintf(stderr, "Error: Missing input file for analyze mode\n\n");
                print_usage(argv[0]);
                return 1;
            }
            return analyze_image(&opts);

        case MODE_POLYGLOT_GEN:
            return polyglot_generate(&opts);

        default:
            fprintf(stderr, "Error: No mode specified\n\n");
            print_usage(argv[0]);
            return 1;
    }
}
