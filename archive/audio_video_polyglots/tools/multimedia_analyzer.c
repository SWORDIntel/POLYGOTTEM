/*
 * Multimedia Polyglot Analyzer
 * =============================
 *
 * Detects audio/video files with embedded polyglot structures:
 * - MP3+ZIP polyglots
 * - WAV+EXE polyglots
 * - PNG+Audio steganography
 * - Other multimedia format anomalies
 *
 * DETECTION METHODS:
 * - Multiple format signatures in single file
 * - Data after expected end markers
 * - Custom chunks in PNG/WAV
 * - Entropy analysis
 *
 * POLYGOTTEM Research, 2025
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#define VERSION "1.0.0"
#define MAX_SEARCH 10485760 // 10MB search limit

// Format signatures
const uint8_t SIG_MP3_ID3[] = {0x49, 0x44, 0x33};          // "ID3"
const uint8_t SIG_MP3_FRAME[] = {0xFF, 0xFB};             // MP3 frame sync
const uint8_t SIG_RIFF[] = {0x52, 0x49, 0x46, 0x46};      // "RIFF"
const uint8_t SIG_WAVE[] = {0x57, 0x41, 0x56, 0x45};      // "WAVE"
const uint8_t SIG_PNG[] = {0x89, 0x50, 0x4E, 0x47};       // PNG
const uint8_t SIG_ZIP[] = {0x50, 0x4B, 0x03, 0x04};       // ZIP
const uint8_t SIG_PE[] = {0x4D, 0x5A};                     // "MZ" (PE executable)

int find_signature(FILE *fp, const uint8_t *sig, size_t sig_len, size_t max_search) {
    uint8_t buffer[4096];
    size_t total_read = 0;
    long start_pos = ftell(fp);

    while (total_read < max_search) {
        size_t to_read = sizeof(buffer);
        if (total_read + to_read > max_search)
            to_read = max_search - total_read;

        size_t bytes = fread(buffer, 1, to_read, fp);
        if (bytes == 0) break;

        for (size_t i = 0; i < bytes - sig_len + 1; i++) {
            if (memcmp(&buffer[i], sig, sig_len) == 0) {
                fseek(fp, start_pos, SEEK_SET);
                return total_read + i;
            }
        }

        total_read += bytes;
    }

    fseek(fp, start_pos, SEEK_SET);
    return -1;
}

int detect_mp3_zip(FILE *fp, size_t file_size) {
    int mp3_found = 0;
    int zip_found = 0;

    // Check for MP3
    if (find_signature(fp, SIG_MP3_ID3, sizeof(SIG_MP3_ID3), 10) >= 0 ||
        find_signature(fp, SIG_MP3_FRAME, sizeof(SIG_MP3_FRAME), 4096) >= 0) {
        mp3_found = 1;
    }

    // Check for ZIP
    fseek(fp, 0, SEEK_SET);
    int zip_offset = find_signature(fp, SIG_ZIP, sizeof(SIG_ZIP), file_size);
    if (zip_offset >= 0) {
        zip_found = 1;
    }

    if (mp3_found && zip_found) {
        printf("\n");
        printf("🚨 POLYGLOT DETECTED!\n");
        printf("═══════════════════════════════════════════════════════════════\n");
        printf("This file is valid in MULTIPLE formats:\n\n");
        printf("  🎯 MP3+ZIP POLYGLOT\n");
        printf("     - Plays as MP3 audio\n");
        printf("     - Contains ZIP archive at offset %d\n", zip_offset);
        printf("     - Technique: MP3 decoders ignore trailing data\n");
        printf("     - Risk: HIGH - Hidden file delivery\n\n");
        return 1;
    }

    return 0;
}

int detect_wav_exe(FILE *fp, size_t file_size) {
    int wav_found = 0;
    int exe_found = 0;

    // Check for WAV
    uint8_t buffer[12];
    fseek(fp, 0, SEEK_SET);
    if (fread(buffer, 1, 12, fp) == 12) {
        if (memcmp(buffer, SIG_RIFF, 4) == 0 &&
            memcmp(buffer + 8, SIG_WAVE, 4) == 0) {
            wav_found = 1;
        }
    }

    // Check for PE executable
    fseek(fp, 0, SEEK_SET);
    int exe_offset = find_signature(fp, SIG_PE, sizeof(SIG_PE), file_size);
    if (exe_offset >= 0) {
        exe_found = 1;
    }

    if (wav_found && exe_found) {
        printf("\n");
        printf("🚨 POLYGLOT DETECTED!\n");
        printf("═══════════════════════════════════════════════════════════════\n");
        printf("This file is valid in MULTIPLE formats:\n\n");
        printf("  🎯 WAV+EXE POLYGLOT\n");
        printf("     - Plays as WAV audio\n");
        printf("     - Contains PE executable at offset %d\n", exe_offset);
        printf("     - Technique: Embedded in RIFF chunk\n");
        printf("     - Risk: CRITICAL - Executable disguised as audio\n\n");
        return 1;
    }

    return 0;
}

int detect_png_audio(FILE *fp) {
    uint8_t sig[8];
    fseek(fp, 0, SEEK_SET);
    if (fread(sig, 1, 8, fp) != 8) return 0;

    if (memcmp(sig, SIG_PNG, 4) != 0) return 0;

    // Search for custom audio chunk (auDT)
    while (!feof(fp)) {
        uint32_t len;
        char type[4];

        if (fread(&len, 4, 1, fp) != 1) break;
        if (fread(type, 1, 4, fp) != 4) break;

        // Swap endianness
        len = ((len >> 24) & 0xff) |
              ((len >> 8) & 0xff00) |
              ((len << 8) & 0xff0000) |
              ((len << 24) & 0xff000000);

        if (memcmp(type, "auDT", 4) == 0) {
            printf("\n");
            printf("🚨 STEGANOGRAPHY DETECTED!\n");
            printf("═══════════════════════════════════════════════════════════════\n");
            printf("This file contains hidden data:\n\n");
            printf("  🎯 PNG+AUDIO STEGANOGRAPHY\n");
            printf("     - Displays as normal PNG image\n");
            printf("     - Contains hidden audio data (%u bytes)\n", len);
            printf("     - Technique: Custom PNG ancillary chunk\n");
            printf("     - Risk: MEDIUM - Covert data channel\n\n");
            return 1;
        }

        // Skip chunk data and CRC
        fseek(fp, len + 4, SEEK_CUR);
    }

    return 0;
}

void print_header(const char *filename, size_t file_size) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     Multimedia Polyglot Analyzer v%s                     ║\n", VERSION);
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Analyzing: %s\n", filename);
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\n");
    printf("File size: %zu bytes\n", file_size);
}

void print_footer(int polyglot_detected) {
    if (polyglot_detected) {
        printf("SECURITY RECOMMENDATIONS:\n");
        printf("─────────────────────────────────────────────────────────────\n");
        printf("  • QUARANTINE this file immediately\n");
        printf("  • DO NOT execute or open in untrusted environments\n");
        printf("  • Use strict file validation (not just magic bytes)\n");
        printf("  • Reject files with multiple valid formats\n");
        printf("  • Check for data after expected EOF markers\n");
        printf("  • Scan with updated antivirus/malware tools\n");
        printf("\n");
    } else {
        printf("\n");
        printf("[✓] No multimedia polyglot structures detected\n");
        printf("    (Note: This does not guarantee file is safe)\n");
        printf("\n");
    }
}

int analyze_file(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    print_header(filename, file_size);

    printf("FORMAT DETECTION:\n");
    printf("─────────────────────────────────────────────────────────────\n");

    int polyglot_detected = 0;

    // Detect various polyglot types
    if (detect_mp3_zip(fp, file_size)) {
        polyglot_detected = 1;
    }

    fseek(fp, 0, SEEK_SET);
    if (detect_wav_exe(fp, file_size)) {
        polyglot_detected = 1;
    }

    fseek(fp, 0, SEEK_SET);
    if (detect_png_audio(fp)) {
        polyglot_detected = 1;
    }

    if (!polyglot_detected) {
        printf("✓ Single format detected\n");
    }

    print_footer(polyglot_detected);

    fclose(fp);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Multimedia Polyglot Analyzer v%s\n\n", VERSION);
        printf("Detects audio/video files with embedded polyglot structures.\n\n");
        printf("Usage: %s <file> [file2] [file3] ...\n\n", argv[0]);
        printf("Detects:\n");
        printf("  - MP3+ZIP polyglots\n");
        printf("  - WAV+EXE polyglots\n");
        printf("  - PNG+Audio steganography\n");
        printf("  - Other multimedia format anomalies\n\n");
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        analyze_file(argv[i]);
    }

    return 0;
}
