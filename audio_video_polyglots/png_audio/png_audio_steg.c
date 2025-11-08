/*
 * PNG+Audio Steganography Tool
 * =============================
 *
 * Creates PNG images with audio data hidden in custom chunks.
 * The PNG displays normally while containing extractable audio.
 *
 * TECHNIQUE:
 * PNG uses chunk-based structure. We add custom chunks (ancillary chunks)
 * that image viewers ignore but our tool can extract.
 *
 * STRUCTURE:
 * +-----------------------------+
 * | PNG Signature               |
 * | IHDR chunk (image header)   |
 * | IDAT chunk (image data)     | <- Browsers display this
 * | auDT chunk (audio data)     | <- Custom chunk (hidden audio)
 * | IEND chunk (end marker)     |
 * +-----------------------------+
 *
 * EXPLOITATION:
 * - Upload "innocent" image to platforms
 * - Extract hidden audio with custom tool
 * - Covert communication channel
 * - Data exfiltration via image uploads
 *
 * ATTRIBUTION:
 * Technique: PNG specification allows ancillary chunks
 * Implementation: POLYGOTTEM Research, 2025
 *
 * COMPILE:
 * gcc -O2 -Wall -o png_audio_steg png_audio_steg.c
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define VERSION "1.0.0"
#define PNG_SIGNATURE "\x89PNG\r\n\x1a\n"

// PNG chunk structure
#pragma pack(push, 1)
typedef struct {
    uint32_t length;  // Big-endian
    char type[4];
} PngChunkHeader;
#pragma pack(pop)

// CRC table for PNG chunks
static uint32_t crc_table[256];
static int crc_table_computed = 0;

void make_crc_table(void) {
    uint32_t c;
    int n, k;
    for (n = 0; n < 256; n++) {
        c = (uint32_t)n;
        for (k = 0; k < 8; k++) {
            if (c & 1)
                c = 0xedb88320L ^ (c >> 1);
            else
                c = c >> 1;
        }
        crc_table[n] = c;
    }
    crc_table_computed = 1;
}

uint32_t calculate_png_crc(const uint8_t *buf, size_t len) {
    uint32_t c = 0xffffffffL;
    size_t n;

    if (!crc_table_computed)
        make_crc_table();

    for (n = 0; n < len; n++) {
        c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
    }
    return c ^ 0xffffffffL;
}

uint32_t swap_uint32(uint32_t val) {
    return ((val >> 24) & 0xff) |
           ((val >> 8) & 0xff00) |
           ((val << 8) & 0xff0000) |
           ((val << 24) & 0xff000000);
}

// Generate minimal PNG (1x1 red pixel)
size_t write_minimal_png(FILE *out) {
    size_t total = 0;

    // PNG signature
    fwrite(PNG_SIGNATURE, 1, 8, out);
    total += 8;

    // IHDR chunk (image header)
    uint8_t ihdr_data[] = {
        0x00, 0x00, 0x00, 0x01, // Width: 1
        0x00, 0x00, 0x00, 0x01, // Height: 1
        0x08,                    // Bit depth: 8
        0x02,                    // Color type: RGB
        0x00,                    // Compression: deflate
        0x00,                    // Filter: none
        0x00                     // Interlace: none
    };

    uint32_t ihdr_len = swap_uint32(sizeof(ihdr_data));
    fwrite(&ihdr_len, 4, 1, out);
    fwrite("IHDR", 1, 4, out);
    fwrite(ihdr_data, 1, sizeof(ihdr_data), out);

    uint8_t crc_buf[4 + sizeof(ihdr_data)];
    memcpy(crc_buf, "IHDR", 4);
    memcpy(crc_buf + 4, ihdr_data, sizeof(ihdr_data));
    uint32_t crc = swap_uint32(calculate_png_crc(crc_buf, sizeof(crc_buf)));
    fwrite(&crc, 4, 1, out);
    total += 4 + 4 + sizeof(ihdr_data) + 4;

    // IDAT chunk (compressed image data - single red pixel)
    uint8_t idat_data[] = {
        0x08, 0x1d,                    // zlib header
        0x01, 0x03, 0x00, 0xfc, 0xff,  // Deflate block
        0x00, 0xff, 0x00, 0x00,        // Red pixel (RGB)
        0x02, 0x00, 0x01, 0xff          // Checksum
    };

    uint32_t idat_len = swap_uint32(sizeof(idat_data));
    fwrite(&idat_len, 4, 1, out);
    fwrite("IDAT", 1, 4, out);
    fwrite(idat_data, 1, sizeof(idat_data), out);

    uint8_t idat_crc_buf[4 + sizeof(idat_data)];
    memcpy(idat_crc_buf, "IDAT", 4);
    memcpy(idat_crc_buf + 4, idat_data, sizeof(idat_data));
    crc = swap_uint32(calculate_png_crc(idat_crc_buf, 4 + sizeof(idat_data)));
    fwrite(&crc, 4, 1, out);
    total += 4 + 4 + sizeof(idat_data) + 4;

    return total;
}

void write_iend_chunk(FILE *out) {
    uint32_t len = 0;
    fwrite(&len, 4, 1, out);
    fwrite("IEND", 1, 4, out);
    uint32_t crc = swap_uint32(calculate_png_crc((uint8_t*)"IEND", 4));
    fwrite(&crc, 4, 1, out);
}

int embed_audio_in_png(const char *png_path, const char *audio_path,
                       const char *output_path) {

    printf("[*] PNG+Audio Steganography Tool v%s\n", VERSION);
    printf("[*] Embedding audio in PNG image...\n\n");

    FILE *out = fopen(output_path, "wb");
    if (!out) {
        perror("fopen output");
        return -1;
    }

    size_t png_size = 0;

    // Phase 1: Write PNG image
    if (png_path) {
        FILE *png = fopen(png_path, "rb");
        if (!png) {
            fprintf(stderr, "[!] Cannot open PNG: %s\n", png_path);
            fclose(out);
            return -1;
        }

        // Copy PNG but stop before IEND
        uint8_t buffer[4096];
        size_t bytes;
        int found_iend = 0;

        while ((bytes = fread(buffer, 1, sizeof(buffer), png)) > 0) {
            // Simple check for IEND chunk (not robust, just for demo)
            for (size_t i = 0; i < bytes - 4; i++) {
                if (memcmp(&buffer[i], "IEND", 4) == 0) {
                    // Write everything before IEND
                    fwrite(buffer, 1, i - 4, out);
                    png_size += i - 4;
                    found_iend = 1;
                    break;
                }
            }
            if (found_iend) break;

            fwrite(buffer, 1, bytes, out);
            png_size += bytes;
        }
        fclose(png);
        printf("[+] Added PNG image: %zu bytes\n", png_size);
    } else {
        // Generate minimal PNG (without IEND)
        png_size = write_minimal_png(out);
        printf("[+] Generated minimal PNG (1x1 red pixel): %zu bytes\n", png_size);
    }

    // Phase 2: Add custom audio chunk (auDT = audio data)
    if (audio_path) {
        FILE *audio = fopen(audio_path, "rb");
        if (!audio) {
            fprintf(stderr, "[!] Cannot open audio: %s\n", audio_path);
            fclose(out);
            return -1;
        }

        // Get audio size
        fseek(audio, 0, SEEK_END);
        uint32_t audio_size = ftell(audio);
        fseek(audio, 0, SEEK_SET);

        // Write custom chunk header
        uint32_t chunk_len = swap_uint32(audio_size);
        fwrite(&chunk_len, 4, 1, out);
        fwrite("auDT", 1, 4, out);  // Custom chunk type (lowercase 'a' = ancillary)

        // Write audio data
        uint8_t *audio_data = malloc(audio_size);
        if (fread(audio_data, 1, audio_size, audio) != audio_size) {
            fprintf(stderr, "[!] Read error\n");
        }
        fwrite(audio_data, 1, audio_size, out);
        fclose(audio);

        // Calculate and write CRC
        uint8_t *crc_buf = malloc(4 + audio_size);
        memcpy(crc_buf, "auDT", 4);
        memcpy(crc_buf + 4, audio_data, audio_size);
        uint32_t crc = swap_uint32(calculate_png_crc(crc_buf, 4 + audio_size));
        fwrite(&crc, 4, 1, out);

        free(audio_data);
        free(crc_buf);

        printf("[+] Embedded audio: %u bytes\n", audio_size);
    }

    // Phase 3: Write IEND chunk
    write_iend_chunk(out);

    fclose(out);

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  PNG+Audio Steganography Complete!                          ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("  File: %s\n\n", output_path);
    printf("  Test as PNG:\n");
    printf("    display %s\n", output_path);
    printf("    firefox %s\n\n", output_path);
    printf("  Extract audio:\n");
    printf("    ./png_audio_steg --extract %s --output audio.bin\n\n", output_path);
    printf("  Image displays normally while hiding audio data!\n\n");
    printf("  ⚠ Use for: Covert channels, data exfiltration research\n\n");

    return 0;
}

int extract_audio_from_png(const char *png_path, const char *output_path) {
    printf("[*] Extracting audio from PNG...\n\n");

    FILE *png = fopen(png_path, "rb");
    if (!png) {
        perror("fopen PNG");
        return -1;
    }

    // Skip PNG signature
    uint8_t sig[8];
    if (fread(sig, 1, 8, png) != 8) {
        fprintf(stderr, "[!] Read error\n");
        fclose(png);
        return -1;
    }

    // Find auDT chunk
    while (!feof(png)) {
        uint32_t len;
        char type[4];

        if (fread(&len, 4, 1, png) != 1) break;
        if (fread(type, 1, 4, png) != 4) break;

        len = swap_uint32(len);

        if (memcmp(type, "auDT", 4) == 0) {
            // Found audio chunk
            printf("[+] Found audio chunk: %u bytes\n", len);

            uint8_t *data = malloc(len);
            if (fread(data, 1, len, png) != len) {
                fprintf(stderr, "[!] Read error\n");
                free(data);
                break;
            }

            FILE *out = fopen(output_path, "wb");
            if (out) {
                fwrite(data, 1, len, out);
                fclose(out);
                printf("[+] Extracted to: %s\n", output_path);
            }

            free(data);
            fclose(png);
            return 0;
        }

        // Skip chunk data and CRC
        fseek(png, len + 4, SEEK_CUR);
    }

    fclose(png);
    fprintf(stderr, "[!] No audio chunk found\n");
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("PNG+Audio Steganography Tool\n\n");
        printf("Usage:\n");
        printf("  Embed:   %s --png image.png --audio file.mp3 --output steg.png\n", argv[0]);
        printf("  Extract: %s --extract steg.png --output audio.bin\n\n", argv[0]);
        printf("Hides audio data in PNG custom chunks (ancillary chunks)\n");
        printf("Image displays normally in all viewers!\n");
        return 1;
    }

    const char *png_file = NULL;
    const char *audio_file = NULL;
    const char *extract_file = NULL;
    const char *output = "output.png";
    int extract_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--png") == 0 && i + 1 < argc) {
            png_file = argv[++i];
        } else if (strcmp(argv[i], "--audio") == 0 && i + 1 < argc) {
            audio_file = argv[++i];
        } else if (strcmp(argv[i], "--extract") == 0 && i + 1 < argc) {
            extract_file = argv[++i];
            extract_mode = 1;
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output = argv[++i];
        }
    }

    if (extract_mode) {
        return extract_audio_from_png(extract_file, output);
    } else {
        return embed_audio_in_png(png_file, audio_file, output);
    }
}
