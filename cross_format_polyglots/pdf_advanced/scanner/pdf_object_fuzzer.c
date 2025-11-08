/*
 * PDF Object Stream Fuzzer
 * ========================
 *
 * Generates malformed PDF objects to test parser robustness and discover
 * vulnerabilities in PDF readers. Focuses on object streams, which are
 * compressed containers for multiple objects.
 *
 * FUZZING TECHNIQUES:
 * 1. Integer overflow in /N (number of objects)
 * 2. Malformed /First offset values
 * 3. Invalid compression filters
 * 4. Boundary condition testing
 * 5. Type confusion attacks
 * 6. Stream length mismatches
 *
 * CVE PATTERNS TARGETED:
 * - CVE-2013-3346: Buffer overflow via malformed objects
 * - CVE-2009-0927: Integer overflow in object streams
 * - CVE-2011-0611: Memory corruption in stream parsing
 *
 * COMPILE:
 * gcc -O2 -Wall -o pdf_fuzzer pdf_object_fuzzer.c -lz
 *
 * POLYGOTTEM Research, 2025
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <zlib.h>

#define VERSION "1.0.0"
#define MAX_FUZZ_ITERATIONS 1000

typedef enum {
    FUZZ_INTEGER_OVERFLOW,
    FUZZ_NEGATIVE_VALUES,
    FUZZ_BOUNDARY_CONDITIONS,
    FUZZ_INVALID_FILTERS,
    FUZZ_LENGTH_MISMATCH,
    FUZZ_TYPE_CONFUSION,
    FUZZ_STREAM_CORRUPTION,
    FUZZ_XREF_MANIPULATION,
    FUZZ_MAX
} FuzzType;

const char *fuzz_type_names[] = {
    "Integer Overflow",
    "Negative Values",
    "Boundary Conditions",
    "Invalid Filters",
    "Length Mismatch",
    "Type Confusion",
    "Stream Corruption",
    "XRef Manipulation"
};

// Compress data using zlib (FlateDecode)
int compress_data(const uint8_t *input, size_t input_len,
                  uint8_t **output, size_t *output_len) {
    *output_len = compressBound(input_len);
    *output = malloc(*output_len);

    int result = compress(*output, (uLongf*)output_len, input, input_len);
    return (result == Z_OK) ? 0 : -1;
}

// Generate fuzzed object stream with integer overflow
void fuzz_integer_overflow(FILE *out, int obj_num) {
    fprintf(out, "%d 0 obj\n", obj_num);
    fprintf(out, "<<\n");
    fprintf(out, "/Type /ObjStm\n");
    fprintf(out, "/N %u\n", 0xFFFFFFFF);  // Maximum uint32 - integer overflow
    fprintf(out, "/First %d\n", -1);       // Negative offset
    fprintf(out, "/Length 100\n");
    fprintf(out, ">>\n");
    fprintf(out, "stream\n");

    // Minimal stream data
    for (int i = 0; i < 100; i++) {
        fputc('A', out);
    }

    fprintf(out, "\nendstream\n");
    fprintf(out, "endobj\n\n");
}

// Generate fuzzed object with boundary conditions
void fuzz_boundary_conditions(FILE *out, int obj_num) {
    fprintf(out, "%d 0 obj\n", obj_num);
    fprintf(out, "<<\n");
    fprintf(out, "/Type /ObjStm\n");
    fprintf(out, "/N 0\n");         // Zero objects
    fprintf(out, "/First 0\n");     // Zero offset
    fprintf(out, "/Length 0\n");    // Zero length
    fprintf(out, ">>\n");
    fprintf(out, "stream\n");
    fprintf(out, "endstream\n");
    fprintf(out, "endobj\n\n");
}

// Generate fuzzed object with invalid filters
void fuzz_invalid_filters(FILE *out, int obj_num) {
    fprintf(out, "%d 0 obj\n", obj_num);
    fprintf(out, "<<\n");
    fprintf(out, "/Type /ObjStm\n");
    fprintf(out, "/N 5\n");
    fprintf(out, "/First 50\n");
    fprintf(out, "/Filter [/FlateDecode /InvalidFilter /ASCIIHexDecode]\n");
    fprintf(out, "/Length 200\n");
    fprintf(out, ">>\n");
    fprintf(out, "stream\n");

    // Random compressed-looking data
    for (int i = 0; i < 200; i++) {
        fprintf(out, "%c", 0x78 + (rand() % 10));
    }

    fprintf(out, "\nendstream\n");
    fprintf(out, "endobj\n\n");
}

// Generate fuzzed object with length mismatch
void fuzz_length_mismatch(FILE *out, int obj_num) {
    fprintf(out, "%d 0 obj\n", obj_num);
    fprintf(out, "<<\n");
    fprintf(out, "/Type /ObjStm\n");
    fprintf(out, "/N 10\n");
    fprintf(out, "/First 100\n");
    fprintf(out, "/Length 5000\n");  // Claims 5000 bytes
    fprintf(out, ">>\n");
    fprintf(out, "stream\n");

    // But only write 100 bytes
    for (int i = 0; i < 100; i++) {
        fputc('B', out);
    }

    fprintf(out, "\nendstream\n");
    fprintf(out, "endobj\n\n");
}

// Generate fuzzed object with type confusion
void fuzz_type_confusion(FILE *out, int obj_num) {
    fprintf(out, "%d 0 obj\n", obj_num);
    fprintf(out, "<<\n");
    fprintf(out, "/Type /ObjStm\n");
    fprintf(out, "/Type /XObject\n");  // Duplicate conflicting type
    fprintf(out, "/Subtype /Image\n");  // Wrong subtype for ObjStm
    fprintf(out, "/N (not_a_number)\n"); // String instead of integer
    fprintf(out, "/First [1 2 3]\n");    // Array instead of integer
    fprintf(out, "/Length << /Nested true >>\n");  // Dict instead of integer
    fprintf(out, ">>\n");
    fprintf(out, "stream\n");
    fprintf(out, "confusion_data\n");
    fprintf(out, "endstream\n");
    fprintf(out, "endobj\n\n");
}

// Generate fuzzed object with stream corruption
void fuzz_stream_corruption(FILE *out, int obj_num) {
    fprintf(out, "%d 0 obj\n", obj_num);
    fprintf(out, "<<\n");
    fprintf(out, "/Type /ObjStm\n");
    fprintf(out, "/N 5\n");
    fprintf(out, "/First 50\n");
    fprintf(out, "/Filter /FlateDecode\n");
    fprintf(out, "/Length 150\n");
    fprintf(out, ">>\n");
    fprintf(out, "stream\n");

    // Corrupted zlib header and random data
    fprintf(out, "\x78\x9C");  // zlib header
    for (int i = 0; i < 148; i++) {
        fprintf(out, "%c", rand() % 256);  // Random corruption
    }

    fprintf(out, "\nendstream\n");
    fprintf(out, "endobj\n\n");
}

// Generate fuzzed xref table
void fuzz_xref_manipulation(FILE *out) {
    fprintf(out, "xref\n");
    fprintf(out, "0 100\n");  // Claims 100 entries

    // Only provide 5 entries
    fprintf(out, "0000000000 65535 f \n");
    fprintf(out, "0000000015 00000 n \n");
    fprintf(out, "9999999999 00000 n \n");  // Invalid offset
    fprintf(out, "-000000001 00000 n \n");  // Negative offset
    fprintf(out, "0000000ABC 00000 n \n");  // Hex in decimal field
}

// Generate fuzzed PDF with specified technique
void generate_fuzzed_pdf(const char *filename, FuzzType fuzz_type, int iteration) {
    FILE *out = fopen(filename, "wb");
    if (!out) {
        perror("fopen");
        return;
    }

    // PDF Header
    fprintf(out, "%%PDF-1.7\n");
    fprintf(out, "%%\xE2\xE3\xCF\xD3\n\n");

    // Catalog
    fprintf(out, "1 0 obj\n");
    fprintf(out, "<< /Type /Catalog /Pages 2 0 R >>\n");
    fprintf(out, "endobj\n\n");

    // Pages
    fprintf(out, "2 0 obj\n");
    fprintf(out, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n");
    fprintf(out, "endobj\n\n");

    // Page
    fprintf(out, "3 0 obj\n");
    fprintf(out, "<<\n");
    fprintf(out, "/Type /Page\n");
    fprintf(out, "/Parent 2 0 R\n");
    fprintf(out, "/MediaBox [0 0 612 792]\n");
    fprintf(out, "/Contents 4 0 R\n");
    fprintf(out, ">>\n");
    fprintf(out, "endobj\n\n");

    // Content
    fprintf(out, "4 0 obj\n");
    fprintf(out, "<< /Length 50 >>\n");
    fprintf(out, "stream\n");
    fprintf(out, "BT /F1 12 Tf 100 700 Td (Fuzz Test %d) Tj ET\n", iteration);
    fprintf(out, "endstream\n");
    fprintf(out, "endobj\n\n");

    // Fuzzed object (object 5)
    switch (fuzz_type) {
        case FUZZ_INTEGER_OVERFLOW:
            fuzz_integer_overflow(out, 5);
            break;
        case FUZZ_BOUNDARY_CONDITIONS:
            fuzz_boundary_conditions(out, 5);
            break;
        case FUZZ_INVALID_FILTERS:
            fuzz_invalid_filters(out, 5);
            break;
        case FUZZ_LENGTH_MISMATCH:
            fuzz_length_mismatch(out, 5);
            break;
        case FUZZ_TYPE_CONFUSION:
            fuzz_type_confusion(out, 5);
            break;
        case FUZZ_STREAM_CORRUPTION:
            fuzz_stream_corruption(out, 5);
            break;
        case FUZZ_XREF_MANIPULATION:
            // Will add to xref below
            break;
        default:
            break;
    }

    // XRef
    long xref_pos = ftell(out);

    if (fuzz_type == FUZZ_XREF_MANIPULATION) {
        fuzz_xref_manipulation(out);
    } else {
        fprintf(out, "xref\n");
        fprintf(out, "0 6\n");
        fprintf(out, "0000000000 65535 f \n");
        fprintf(out, "0000000015 00000 n \n");
        fprintf(out, "0000000074 00000 n \n");
        fprintf(out, "0000000133 00000 n \n");
        fprintf(out, "0000000234 00000 n \n");
        fprintf(out, "0000000334 00000 n \n");
    }

    // Trailer
    fprintf(out, "trailer\n");
    fprintf(out, "<<\n");
    fprintf(out, "/Size 6\n");
    fprintf(out, "/Root 1 0 R\n");
    fprintf(out, ">>\n");
    fprintf(out, "startxref\n");
    fprintf(out, "%ld\n", xref_pos);
    fprintf(out, "%%%%EOF\n");

    fclose(out);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("PDF Object Stream Fuzzer v%s\n\n", VERSION);
        printf("Generates malformed PDFs to test parser robustness.\n\n");
        printf("Usage: %s [OPTIONS]\n\n", argv[0]);
        printf("Options:\n");
        printf("  --type TYPE      Fuzzing type (0-%d)\n", FUZZ_MAX - 1);
        printf("  --iterations N   Number of iterations (default: 10)\n");
        printf("  --output DIR     Output directory (default: fuzzed/)\n");
        printf("  --all            Generate all fuzzing types\n\n");
        printf("Fuzzing Types:\n");
        for (int i = 0; i < FUZZ_MAX; i++) {
            printf("  %d: %s\n", i, fuzz_type_names[i]);
        }
        printf("\nTargeted CVEs:\n");
        printf("  CVE-2013-3346: Buffer overflow via malformed objects\n");
        printf("  CVE-2009-0927: Integer overflow in object streams\n");
        printf("  CVE-2011-0611: Memory corruption in stream parsing\n\n");
        printf("Example:\n");
        printf("  %s --all --iterations 100 --output fuzz_corpus/\n\n", argv[0]);
        return 1;
    }

    int iterations = 10;
    const char *output_dir = "fuzzed";
    int fuzz_type = -1;
    int all_types = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
            fuzz_type = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            iterations = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output_dir = argv[++i];
        } else if (strcmp(argv[i], "--all") == 0) {
            all_types = 1;
        }
    }

    srand(time(NULL));

    // Create output directory
    char mkdir_cmd[256];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", output_dir);
    system(mkdir_cmd);

    printf("[*] PDF Object Stream Fuzzer v%s\n", VERSION);
    printf("[*] Generating fuzzed PDFs...\n\n");

    int total_generated = 0;

    if (all_types) {
        // Generate all fuzzing types
        for (int type = 0; type < FUZZ_MAX; type++) {
            printf("[+] Fuzzing Type: %s\n", fuzz_type_names[type]);

            for (int iter = 0; iter < iterations; iter++) {
                char filename[512];
                snprintf(filename, sizeof(filename),
                        "%s/fuzz_%s_%04d.pdf",
                        output_dir,
                        fuzz_type_names[type],
                        iter);

                // Replace spaces with underscores in filename
                for (char *p = filename; *p; p++) {
                    if (*p == ' ') *p = '_';
                }

                generate_fuzzed_pdf(filename, type, iter);
                total_generated++;
            }
            printf("    Generated %d samples\n", iterations);
        }
    } else if (fuzz_type >= 0 && fuzz_type < FUZZ_MAX) {
        // Generate specific type
        printf("[+] Fuzzing Type: %s\n", fuzz_type_names[fuzz_type]);

        for (int iter = 0; iter < iterations; iter++) {
            char filename[512];
            snprintf(filename, sizeof(filename),
                    "%s/fuzz_%s_%04d.pdf",
                    output_dir,
                    fuzz_type_names[fuzz_type],
                    iter);

            for (char *p = filename; *p; p++) {
                if (*p == ' ') *p = '_';
            }

            generate_fuzzed_pdf(filename, fuzz_type, iter);
            total_generated++;
        }
        printf("    Generated %d samples\n", iterations);
    } else {
        fprintf(stderr, "[!] Invalid fuzzing type\n");
        return 1;
    }

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  PDF Fuzzing Complete!                                      ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("  Total PDFs generated: %d\n", total_generated);
    printf("  Output directory: %s/\n\n", output_dir);
    printf("  🔬 TESTING:\n");
    printf("     Test with: for f in %s/*.pdf; do pdfinfo \"$f\" 2>&1; done\n", output_dir);
    printf("     Crash detection: dmesg | tail\n");
    printf("     Memory errors: valgrind pdfinfo %s/fuzz_*.pdf\n\n", output_dir);
    printf("  ⚠️  Run against target PDF readers in isolated environment!\n\n");

    return 0;
}
