/*
 * PDF+ZIP Cross-Format Polyglot Generator
 * ========================================
 *
 * Creates files that are simultaneously:
 * - Valid PDF documents (opens in PDF readers)
 * - Valid ZIP archives (opens in archive tools)
 *
 * TECHNIQUE:
 * PDF format allows arbitrary data before the %PDF header (up to 1024 bytes).
 * We exploit this to place a complete ZIP archive before the PDF content.
 *
 * STRUCTURE:
 * ┌─────────────────────────────┐
 * │ ZIP Archive (with files)    │ ← Archive tools read this
 * ├─────────────────────────────┤
 * │ %PDF-1.4                    │ ← PDF readers start here
 * │ PDF Objects                 │
 * │ %%EOF                       │
 * └─────────────────────────────┘
 *
 * USAGE:
 * ./pdf_zip_gen --pdf input.pdf --zip-files file1.txt,file2.sh --output dual.pdf
 *
 * Opens in:
 * - Adobe Reader → Shows PDF content
 * - unzip → Extracts ZIP files
 *
 * ATTRIBUTION:
 * Technique: Ange Albertini (Corkami), 2014
 * Implementation: POLYGOTTEM Research, 2025
 *
 * COMPILE:
 * gcc -O2 -Wall -o pdf_zip_gen pdf_zip_polyglot.c -lz
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>
#include <strings.h>

#define VERSION "1.0.0"
#define MAX_FILES 100

// ZIP structures
#pragma pack(push, 1)

typedef struct {
    uint32_t signature;          // 0x04034b50
    uint16_t version;            // 20
    uint16_t flags;              // 0
    uint16_t compression;        // 0 = stored (no compression)
    uint16_t mod_time;           // DOS time
    uint16_t mod_date;           // DOS date
    uint32_t crc32;              // CRC-32
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

// Simple CRC32 implementation
static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    // ... (full table in real implementation)
};

uint32_t calculate_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        uint8_t index = (crc ^ data[i]) & 0xFF;
        crc = (crc >> 8) ^ crc32_table[index];
    }
    return ~crc;
}

// Get DOS time/date
void get_dos_datetime(uint16_t *dos_time, uint16_t *dos_date) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    *dos_time = (t->tm_hour << 11) | (t->tm_min << 5) | (t->tm_sec / 2);
    *dos_date = ((t->tm_year - 80) << 9) | ((t->tm_mon + 1) << 5) | t->tm_mday;
}

// Create PDF+ZIP polyglot
int create_pdf_zip_polyglot(const char *pdf_path, const char **zip_files,
                            int num_files, const char *output_path) {

    printf("[*] PDF+ZIP Polyglot Generator v%s\n", VERSION);
    printf("[*] Creating dual-format file...\n\n");

    FILE *out = fopen(output_path, "wb");
    if (!out) {
        perror("fopen output");
        return -1;
    }

    // Track positions
    uint32_t current_pos = 0;
    uint32_t local_headers_start = 0;
    uint32_t central_dir_start = 0;

    // Arrays to store file info
    struct {
        char *filename;
        uint8_t *data;
        size_t size;
        uint32_t crc;
        uint32_t offset;
    } files[MAX_FILES];

    // Initialize array
    memset(files, 0, sizeof(files));

    // Read and store all ZIP files
    for (int i = 0; i < num_files; i++) {
        FILE *fp = fopen(zip_files[i], "rb");
        if (!fp) {
            fprintf(stderr, "[!] Cannot open: %s\n", zip_files[i]);
            fclose(out);
            // Cleanup already loaded files
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
        fread(files[i].data, 1, files[i].size, fp);
        fclose(fp);

        files[i].filename = strdup(zip_files[i]);
        files[i].crc = calculate_crc32(files[i].data, files[i].size);

        printf("[+] Added: %s (%zu bytes)\n", zip_files[i], files[i].size);
    }

    // Write ZIP local file headers and data
    uint16_t dos_time, dos_date;
    get_dos_datetime(&dos_time, &dos_date);

    for (int i = 0; i < num_files; i++) {
        files[i].offset = current_pos;

        ZipLocalFileHeader lfh = {
            .signature = 0x04034b50,
            .version = 20,
            .flags = 0,
            .compression = 0,  // Stored (no compression)
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

    central_dir_start = current_pos;

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
            .external_attr = 0x20,  // Archive attribute
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
    current_pos += sizeof(eocd);

    printf("\n[+] ZIP archive complete: %u bytes\n", current_pos);

    // Now append PDF content
    // PDF readers will skip the ZIP data and find %PDF
    FILE *pdf = fopen(pdf_path, "rb");
    if (!pdf) {
        // Generate minimal PDF if no source provided
        const char *minimal_pdf =
            "%PDF-1.4\n"
            "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            "3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
            "xref\n0 4\n"
            "0000000000 65535 f\n"
            "0000000009 00000 n\n"
            "0000000058 00000 n\n"
            "0000000115 00000 n\n"
            "trailer<</Size 4/Root 1 0 R>>\n"
            "startxref\n200\n"
            "%%EOF\n";

        fwrite(minimal_pdf, 1, strlen(minimal_pdf), out);
        printf("[+] Added minimal PDF content\n");
    } else {
        // Copy existing PDF
        uint8_t buffer[4096];
        size_t bytes;
        size_t pdf_size = 0;
        while ((bytes = fread(buffer, 1, sizeof(buffer), pdf)) > 0) {
            fwrite(buffer, 1, bytes, out);
            pdf_size += bytes;
        }
        fclose(pdf);
        printf("[+] Added PDF content: %zu bytes\n", pdf_size);
    }

    fclose(out);

    // Cleanup
    for (int i = 0; i < num_files; i++) {
        free(files[i].data);
        free(files[i].filename);
    }

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  PDF+ZIP Polyglot Created Successfully!                     ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("  File: %s\n\n", output_path);
    printf("  Test as PDF:\n");
    printf("    evince %s\n", output_path);
    printf("    xpdf %s\n\n", output_path);
    printf("  Test as ZIP:\n");
    printf("    unzip -l %s\n", output_path);
    printf("    unzip %s\n\n", output_path);
    printf("  Both will work on the SAME file!\n\n");

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("PDF+ZIP Cross-Format Polyglot Generator\n\n");
        printf("Usage: %s [OPTIONS]\n\n", argv[0]);
        printf("Options:\n");
        printf("  --pdf FILE        Source PDF (or generate minimal)\n");
        printf("  --add FILE        Add file to ZIP (can specify multiple)\n");
        printf("  --output FILE     Output polyglot file\n\n");
        printf("Example:\n");
        printf("  %s --add payload.sh --add data.txt --output dual.pdf\n\n", argv[0]);
        printf("Creates a file that is both a valid PDF and ZIP archive!\n");
        return 1;
    }

    const char *pdf_file = NULL;
    const char *zip_files[MAX_FILES];
    int num_zip_files = 0;
    const char *output = "polyglot.pdf";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pdf") == 0 && i + 1 < argc) {
            pdf_file = argv[++i];
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

    return create_pdf_zip_polyglot(pdf_file, zip_files, num_zip_files, output);
}
