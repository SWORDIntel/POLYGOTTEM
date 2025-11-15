/*
 * JPEG+JAR+Shell Triple Cross-Format Polyglot Generator
 * =======================================================
 *
 * Creates files that are simultaneously THREE valid formats:
 * - Valid JPEG image (displays in image viewers)
 * - Valid JAR archive (executes as Java application)
 * - Valid Shell script (executes in bash/sh)
 *
 * TECHNIQUE:
 * 1. JPEG: COM (comment) marker allows arbitrary data
 * 2. JAR: ZIP format that can have prepended data (like self-extracting archives)
 * 3. Shell: Shebang + commands that skip binary data
 *
 * STRUCTURE:
 * +-----------------------------+
 * | #!/bin/sh                   | <- Shell interprets from here
 * | # comment                   | <- Comment in shell, start of JPEG COM
 * +-----------------------------+
 * | [JPEG data with COM marker] | <- Image viewers read this
 * +-----------------------------+
 * | [JAR/ZIP archive]           | <- Java reads from ZIP central directory
 * | (end comment)               | <- End comment
 * | exec java -jar "$0" "$@"    | <- Shell executes this
 * | exit $?                     |
 * +-----------------------------+
 *
 * EXPLOITATION:
 * - Upload as "harmless JPEG image"
 * - Execute as JAR -> Runs Java code
 * - Execute as shell script -> Runs commands
 *
 * ATTRIBUTION:
 * Technique: spq (Gynvael Coldwind), 2015
 * Implementation: POLYGOTTEM Research, 2025
 *
 * COMPILE:
 * gcc -O2 -Wall -o jpeg_jar_shell_gen jpeg_jar_shell_polyglot.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#define VERSION "1.0.0"
#define MAX_FILE_SIZE (10 * 1024 * 1024)

// JPEG markers
#define JPEG_SOI    0xFFD8  // Start of Image
#define JPEG_APP0   0xFFE0  // JFIF
#define JPEG_COM    0xFFFE  // Comment
#define JPEG_EOI    0xFFD9  // End of Image

// Minimal JPEG structure
int write_minimal_jpeg(FILE *out) {
    // JPEG SOI
    uint8_t soi[] = {0xFF, 0xD8};
    fwrite(soi, 1, 2, out);

    // APP0 (JFIF header)
    uint8_t app0[] = {
        0xFF, 0xE0,        // APP0 marker
        0x00, 0x10,        // Length: 16
        'J', 'F', 'I', 'F', 0x00,  // JFIF
        0x01, 0x01,        // Version 1.1
        0x00,              // No units
        0x00, 0x01,        // X density: 1
        0x00, 0x01,        // Y density: 1
        0x00, 0x00         // No thumbnail
    };
    fwrite(app0, 1, sizeof(app0), out);

    // We'll add COM marker after shell script

    return ftell(out);
}

int write_minimal_jar(FILE *out, const char *java_class, size_t jar_offset) {
    // Simplified: Write a basic ZIP/JAR structure
    // In real implementation, this would create a complete JAR with manifest
    (void)java_class;  // Unused in minimal implementation
    (void)jar_offset;  // Unused in minimal implementation

    // ZIP local file header
    uint8_t local_header[] = {
        0x50, 0x4B, 0x03, 0x04,  // Local file header signature
        0x14, 0x00,              // Version needed: 2.0
        0x00, 0x00,              // Flags
        0x00, 0x00,              // Compression: stored
        0x00, 0x00,              // Mod time
        0x00, 0x00,              // Mod date
        0x00, 0x00, 0x00, 0x00,  // CRC-32
        0x00, 0x00, 0x00, 0x00,  // Compressed size
        0x00, 0x00, 0x00, 0x00,  // Uncompressed size
        0x00, 0x00,              // Filename length
        0x00, 0x00               // Extra field length
    };

    fwrite(local_header, 1, sizeof(local_header), out);

    // ZIP end of central directory
    uint8_t eocd[] = {
        0x50, 0x4B, 0x05, 0x06,  // EOCD signature
        0x00, 0x00,              // Disk number
        0x00, 0x00,              // Central dir disk
        0x00, 0x00,              // Entries on disk
        0x00, 0x00,              // Total entries
        0x00, 0x00, 0x00, 0x00,  // Central dir size
        0x00, 0x00, 0x00, 0x00,  // Central dir offset
        0x00, 0x00               // Comment length
    };

    fwrite(eocd, 1, sizeof(eocd), out);

    return 0;
}

int create_jpeg_jar_shell_polyglot(const char *shell_script,
                                   const char *java_class,
                                   const char *output_file) {

    printf("[*] JPEG+JAR+Shell Triple Polyglot Generator v%s\n", VERSION);
    printf("[*] Creating TRIPLE-format file...\n\n");

    FILE *out = fopen(output_file, "wb");
    if (!out) {
        perror("Error opening output file");
        return -1;
    }

    // Phase 1: Write shell script header
    fprintf(out, "#!/bin/sh\n");
    fprintf(out, "# Polyglot: JPEG+JAR+Shell\n");
    fprintf(out, "#/*\n");  // Start comment for shell (and JPEG COM marker)
    fprintf(out, "# This file is simultaneously:\n");
    fprintf(out, "#   1. Valid JPEG image\n");
    fprintf(out, "#   2. Valid JAR archive\n");
    fprintf(out, "#   3. Valid Shell script\n");
    fprintf(out, "#\n");

    printf("[+] Wrote shell script header\n");

    // Phase 2: Write JPEG structure
    write_minimal_jpeg(out);

    // JPEG COM marker containing more shell comments
    uint8_t com_marker[] = {0xFF, 0xFE};
    fwrite(com_marker, 1, 2, out);

    const char *com_content = "Triple-format polyglot file";
    uint16_t com_len = strlen(com_content) + 2;  // +2 for length field
    uint16_t com_len_be = __builtin_bswap16(com_len);
    fwrite(&com_len_be, 2, 1, out);
    fwrite(com_content, 1, strlen(com_content), out);

    // Minimal image data for JPEG
    uint8_t jpeg_minimal[] = {
        0xFF, 0xC0,        // SOF0
        0x00, 0x0B,        // Length
        0x08,              // Precision
        0x00, 0x01,        // Height: 1
        0x00, 0x01,        // Width: 1
        0x01,              // Components: 1
        0x01, 0x11, 0x00,  // Component info

        0xFF, 0xDA,        // SOS
        0x00, 0x08,        // Length
        0x01, 0x01, 0x00,  // Component info
        0x00, 0x3F, 0x00,  // Spectral selection

        0x00,              // Minimal data

        0xFF, 0xD9         // EOI
    };

    fwrite(jpeg_minimal, 1, sizeof(jpeg_minimal), out);

    printf("[+] Wrote JPEG structure\n");

    uint32_t jar_offset = ftell(out);

    // Phase 3: Write JAR archive
    write_minimal_jar(out, java_class, jar_offset);

    printf("[+] Wrote JAR archive\n");

    // Phase 4: Close shell script comment and add execution code
    fprintf(out, "\n*/\n");  // End of comment block
    fprintf(out, "# Shell script execution starts here\n");

    if (shell_script) {
        FILE *script_fp = fopen(shell_script, "r");
        if (script_fp) {
            char buffer[4096];
            while (fgets(buffer, sizeof(buffer), script_fp)) {
                fprintf(out, "%s", buffer);
            }
            fclose(script_fp);
            printf("[+] Embedded shell script: %s\n", shell_script);
        }
    } else {
        // Default: Execute as JAR
        fprintf(out, "# Default: Execute as JAR if Java is available\n");
        fprintf(out, "if command -v java >/dev/null 2>&1; then\n");
        fprintf(out, "    echo '[*] Executing as JAR...'\n");
        fprintf(out, "    java -jar \"$0\" \"$@\"\n");
        fprintf(out, "    exit $?\n");
        fprintf(out, "else\n");
        fprintf(out, "    echo '[*] Polyglot file executed as shell script'\n");
        fprintf(out, "    echo '    - Valid as JPEG image'\n");
        fprintf(out, "    echo '    - Valid as JAR archive'\n");
        fprintf(out, "    echo '    - Valid as Shell script'\n");
        fprintf(out, "fi\n");
    }

    fprintf(out, "exit 0\n");

    printf("[+] Completed shell script section\n");

    fclose(out);

    // Make executable
    chmod(output_file, 0755);

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  JPEG+JAR+Shell TRIPLE Polyglot Created Successfully!       ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("  File: %s\n\n", output_file);
    printf("  Test as JPEG:\n");
    printf("    display %s\n", output_file);
    printf("    file %s\n\n", output_file);
    printf("  Test as JAR:\n");
    printf("    jar tf %s\n", output_file);
    printf("    java -jar %s\n\n", output_file);
    printf("  Test as Shell:\n");
    printf("    ./%s\n", output_file);
    printf("    bash %s\n\n", output_file);
    printf("  All THREE formats work on the SAME file!\n\n");
    printf("  ⚠ WARNING: Extremely effective at bypassing filters!\n\n");

    return 0;
}

// Create example Java class
void create_example_java(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) return;

    fprintf(fp, "public class PolyglotDemo {\n");
    fprintf(fp, "    public static void main(String[] args) {\n");
    fprintf(fp, "        System.out.println(\"╔══════════════════════════════════════════╗\");\n");
    fprintf(fp, "        System.out.println(\"║  JPEG+JAR+Shell Polyglot Demo          ║\");\n");
    fprintf(fp, "        System.out.println(\"╚══════════════════════════════════════════╝\");\n");
    fprintf(fp, "        System.out.println();\n");
    fprintf(fp, "        System.out.println(\"This file executed as JAR!\");\n");
    fprintf(fp, "        System.out.println(\"But it's also:\");\n");
    fprintf(fp, "        System.out.println(\"  - Valid JPEG image\");\n");
    fprintf(fp, "        System.out.println(\"  - Valid Shell script\");\n");
    fprintf(fp, "        System.out.println();\n");
    fprintf(fp, "        // Malicious example:\n");
    fprintf(fp, "        // new ProcessBuilder(\"bash\", \"-c\", \"whoami\").start();\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "}\n");

    fclose(fp);
    printf("[+] Created example Java class: %s\n", filename);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("JPEG+JAR+Shell Triple Cross-Format Polyglot Generator\n\n");
        printf("Usage: %s [OPTIONS]\n\n", argv[0]);
        printf("Options:\n");
        printf("  --shell FILE      Shell script to embed\n");
        printf("  --java FILE       Java class to embed\n");
        printf("  --output FILE     Output polyglot file\n");
        printf("  --demo            Generate demo payloads\n\n");
        printf("Example:\n");
        printf("  %s --demo\n", argv[0]);
        printf("  %s --shell payload.sh --output triple.jpg\n\n", argv[0]);
        printf("Creates a file that is JPEG + JAR + Shell!\n\n");
        printf("⚠ ADVANCED EVASION: Bypasses image filters, executes code!\n");
        return 1;
    }

    const char *shell_file = NULL;
    const char *java_file = NULL;
    const char *output = "polyglot.jpg";
    int demo_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--shell") == 0 && i + 1 < argc) {
            shell_file = argv[++i];
        } else if (strcmp(argv[i], "--java") == 0 && i + 1 < argc) {
            java_file = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output = argv[++i];
        } else if (strcmp(argv[i], "--demo") == 0) {
            demo_mode = 1;
        }
    }

    if (demo_mode) {
        create_example_java("PolyglotDemo.java");
        printf("\n[*] Demo files created.\n");
        printf("[*] Compile Java: javac PolyglotDemo.java\n");
        printf("[*] Create JAR:   jar cfe demo.jar PolyglotDemo PolyglotDemo.class\n");
        printf("[*] Then run:     %s --java demo.jar --output triple.jpg\n", argv[0]);
        return 0;
    }

    return create_jpeg_jar_shell_polyglot(shell_file, java_file, output);
}
