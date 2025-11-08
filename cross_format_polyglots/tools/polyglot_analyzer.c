/*
 * Cross-Format Polyglot Analyzer
 * ================================
 *
 * Detects and analyzes files that are valid in multiple formats simultaneously.
 *
 * CAPABILITIES:
 * - Detects PDF+ZIP polyglots
 * - Detects GIF+HTML polyglots
 * - Detects JPEG+JAR polyglots
 * - Identifies executable permissions on images
 * - Analyzes file structure mismatches
 *
 * COMPILE:
 * gcc -O2 -Wall -o polyglot_analyzer polyglot_analyzer.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#define VERSION "1.0.0"

// Format signatures
const uint8_t PDF_SIG[] = {0x25, 0x50, 0x44, 0x46};  // %PDF
const uint8_t ZIP_SIG[] = {0x50, 0x4B, 0x03, 0x04};  // PK..
const uint8_t GIF_SIG[] = {0x47, 0x49, 0x46, 0x38};  // GIF8
const uint8_t JPEG_SIG[] = {0xFF, 0xD8, 0xFF};       // JPEG SOI
const uint8_t HTML_SIG1[] = {'<', '!', 'D', 'O', 'C', 'T', 'Y', 'P', 'E'};
const uint8_t HTML_SIG2[] = {'<', 'h', 't', 'm', 'l'};
const uint8_t SHEBANG[] = {'#', '!'};
const uint8_t JAR_MANIFEST[] = {'M', 'a', 'n', 'i', 'f', 'e', 's', 't'};

typedef struct {
    int is_pdf;
    int is_zip;
    int is_gif;
    int is_jpeg;
    int is_html;
    int is_shell;
    int is_jar;
    int has_shebang;
    int is_executable;
} FormatFlags;

// Search for signature in file
int find_signature(FILE *fp, const uint8_t *sig, size_t sig_len, size_t max_search) {
    uint8_t buffer[4096];
    size_t total_read = 0;

    fseek(fp, 0, SEEK_SET);

    while (total_read < max_search) {
        size_t to_read = (max_search - total_read > sizeof(buffer)) ?
                        sizeof(buffer) : (max_search - total_read);

        size_t bytes_read = fread(buffer, 1, to_read, fp);
        if (bytes_read == 0) break;

        for (size_t i = 0; i <= bytes_read - sig_len; i++) {
            if (memcmp(buffer + i, sig, sig_len) == 0) {
                return total_read + i;
            }
        }

        total_read += bytes_read;
    }

    return -1;
}

void analyze_file(const char *filename) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║       Cross-Format Polyglot Analyzer v%s                ║\n", VERSION);
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Analyzing: %s\n", filename);
    printf("═══════════════════════════════════════════════════════════════\n\n");

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Error opening file");
        return;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    printf("File size: %zu bytes\n\n", file_size);

    // Check file permissions
    struct stat st;
    stat(filename, &st);
    int is_executable = (st.st_mode & S_IXUSR) || (st.st_mode & S_IXGRP) || (st.st_mode & S_IXOTH);

    // Read first 4KB for analysis
    uint8_t header[4096];
    size_t header_size = fread(header, 1, sizeof(header), fp);

    FormatFlags formats = {0};

    // Check format signatures
    printf("FORMAT DETECTION:\n");
    printf("─────────────────────────────────────────────────────────────\n");

    // PDF check
    int pdf_pos = find_signature(fp, PDF_SIG, sizeof(PDF_SIG), file_size);
    if (pdf_pos >= 0) {
        formats.is_pdf = 1;
        printf("✓ PDF signature found at offset %d\n", pdf_pos);
        if (pdf_pos > 0) {
            printf("  ⚠ WARNING: PDF signature not at start (offset %d)\n", pdf_pos);
            printf("  This could indicate data prepended before PDF\n");
        }
    }

    // ZIP/JAR check
    int zip_pos = find_signature(fp, ZIP_SIG, sizeof(ZIP_SIG), file_size);
    if (zip_pos >= 0) {
        formats.is_zip = 1;
        printf("✓ ZIP signature found at offset %d\n", zip_pos);
        if (zip_pos > 0) {
            printf("  ⚠ WARNING: ZIP signature not at start (offset %d)\n", zip_pos);
        }

        // Check if it's a JAR (has META-INF/MANIFEST.MF)
        int manifest_pos = find_signature(fp, JAR_MANIFEST, sizeof(JAR_MANIFEST), file_size);
        if (manifest_pos >= 0) {
            formats.is_jar = 1;
            printf("  ✓ JAR manifest detected → This is a JAR file\n");
        }
    }

    // GIF check
    if (header_size >= 4 && memcmp(header, GIF_SIG, sizeof(GIF_SIG)) == 0) {
        formats.is_gif = 1;
        printf("✓ GIF signature found at offset 0\n");
    }

    // JPEG check
    if (header_size >= 3 && memcmp(header, JPEG_SIG, sizeof(JPEG_SIG)) == 0) {
        formats.is_jpeg = 1;
        printf("✓ JPEG signature found at offset 0\n");
    }

    // HTML check
    int html_pos1 = find_signature(fp, HTML_SIG1, sizeof(HTML_SIG1), 4096);
    int html_pos2 = find_signature(fp, HTML_SIG2, sizeof(HTML_SIG2), 4096);
    if (html_pos1 >= 0 || html_pos2 >= 0) {
        formats.is_html = 1;
        int pos = (html_pos1 >= 0) ? html_pos1 : html_pos2;
        printf("✓ HTML signature found at offset %d\n", pos);
        if (pos > 0) {
            printf("  ⚠ WARNING: HTML not at start → Possible polyglot\n");
        }
    }

    // Shebang check
    if (header_size >= 2 && memcmp(header, SHEBANG, sizeof(SHEBANG)) == 0) {
        formats.has_shebang = 1;
        formats.is_shell = 1;
        printf("✓ Shebang (#!) found at offset 0\n");
        printf("  This file can be executed as a script\n");
    }

    // Executable permission check
    if (is_executable) {
        formats.is_executable = 1;
        printf("✓ File has executable permissions\n");
    }

    printf("\n");

    // Polyglot detection
    int format_count = formats.is_pdf + formats.is_zip + formats.is_gif +
                      formats.is_jpeg + formats.is_html + formats.is_shell;

    if (format_count >= 2) {
        printf("🚨 POLYGLOT DETECTED!\n");
        printf("═══════════════════════════════════════════════════════════════\n");
        printf("This file is valid in MULTIPLE formats:\n\n");

        if (formats.is_pdf && formats.is_zip) {
            printf("  🎯 PDF+ZIP POLYGLOT\n");
            printf("     - Opens as PDF in readers\n");
            printf("     - Opens as ZIP in archive tools\n");
            printf("     - Technique: PDF allows prepended data\n");
            printf("     - Risk: HIGH - Can hide malicious files\n\n");
        }

        if (formats.is_gif && formats.is_html) {
            printf("  🎯 GIF+HTML POLYGLOT\n");
            printf("     - Displays as image in viewers\n");
            printf("     - Executes as HTML in browsers\n");
            printf("     - Technique: HTML comment embedding\n");
            printf("     - Risk: CRITICAL - XSS via image upload\n\n");
        }

        if (formats.is_jpeg && formats.is_jar && formats.is_shell) {
            printf("  🎯 JPEG+JAR+SHELL TRIPLE POLYGLOT\n");
            printf("     - Displays as JPEG image\n");
            printf("     - Executes as JAR (Java)\n");
            printf("     - Executes as shell script\n");
            printf("     - Technique: JPEG COM + JAR prepended data + shebang\n");
            printf("     - Risk: CRITICAL - Multi-vector code execution\n\n");
        }

        if (formats.is_jpeg && formats.is_shell) {
            printf("  🎯 JPEG+SHELL POLYGLOT\n");
            printf("     - Displays as JPEG image\n");
            printf("     - Executes as shell script\n");
            printf("     - Risk: HIGH - Code execution via image\n\n");
        }

        if (formats.is_gif && formats.is_shell) {
            printf("  🎯 GIF+SHELL POLYGLOT\n");
            printf("     - Displays as GIF image\n");
            printf("     - Executes as shell script\n");
            printf("     - Risk: HIGH - Code execution via image\n\n");
        }

        printf("SECURITY RECOMMENDATIONS:\n");
        printf("─────────────────────────────────────────────────────────────\n");
        printf("  • QUARANTINE this file immediately\n");
        printf("  • DO NOT open in untrusted environments\n");
        printf("  • Use strict file validation (not just magic bytes)\n");
        printf("  • Reject files with multiple valid formats\n");
        printf("  • Check for data after expected EOF markers\n");
        printf("  • Scan with updated antivirus/malware tools\n\n");

    } else if (format_count == 1) {
        printf("✅ CLEAN FILE (Single Format)\n");
        printf("═══════════════════════════════════════════════════════════════\n");
        printf("No polyglot detected. File appears to be single-format.\n\n");
    } else {
        printf("❓ UNKNOWN FORMAT\n");
        printf("═══════════════════════════════════════════════════════════════\n");
        printf("Could not identify file format. Manual analysis recommended.\n\n");
    }

    fclose(fp);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Cross-Format Polyglot Analyzer v%s\n\n", VERSION);
        printf("Usage: %s <file> [file2] [file3] ...\n\n", argv[0]);
        printf("Detects files that are valid in multiple formats:\n");
        printf("  • PDF+ZIP polyglots\n");
        printf("  • GIF+HTML polyglots\n");
        printf("  • JPEG+JAR+Shell triple polyglots\n");
        printf("  • Other cross-format files\n\n");
        printf("Example:\n");
        printf("  %s suspicious.gif\n", argv[0]);
        printf("  %s *.jpg *.pdf\n\n", argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        analyze_file(argv[i]);
    }

    return 0;
}
