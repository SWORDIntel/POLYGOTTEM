/*
 * PDF Vulnerability Scanner
 * =========================
 *
 * Scans PDF files for known vulnerability patterns and suspicious structures.
 * Detects exploitation attempts based on CVE patterns and malicious objects.
 *
 * DETECTION CAPABILITIES:
 * - JavaScript presence and suspicious code patterns
 * - Launch actions and command execution
 * - Embedded files and suspicious attachments
 * - OpenAction auto-execution
 * - Malformed object streams
 * - Integer overflow attempts
 * - Flash/SWF embedded content
 * - XFA form exploits
 * - Suspicious filters
 * - Abnormal structure
 *
 * CVE PATTERNS DETECTED:
 * - CVE-2010-1297: util.printf() overflow
 * - CVE-2013-0640: JavaScript API exploits
 * - CVE-2018-4990: Launch action injection
 * - CVE-2009-0927: JBIG2Decode overflow
 * - CVE-2010-0188: LibTIFF overflow
 * - CVE-2011-0611: Flash exploitation
 * - CVE-2013-3346: Malformed objects
 * - CVE-2016-4191: Use-after-free patterns
 *
 * COMPILE:
 * gcc -O2 -Wall -o pdf_scanner pdf_vuln_scanner.c
 *
 * POLYGOTTEM Research, 2025
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#define VERSION "1.0.0"
#define MAX_FILE_SIZE (50 * 1024 * 1024)  // 50MB limit

typedef struct {
    int javascript_count;
    int openaction_found;
    int launch_action_count;
    int embedded_files;
    int flash_content;
    int xfa_forms;
    int suspicious_filters;
    int malformed_objects;
    int extreme_values;
    int uri_actions;
    int aa_actions;

    // CVE-specific detections
    int cve_2010_1297;  // util.printf
    int cve_2013_0640;  // JavaScript API
    int cve_2018_4990;  // Launch
    int cve_2009_0927;  // JBIG2
    int cve_2010_0188;  // LibTIFF
    int cve_2011_0611;  // Flash
    int cve_2013_3346;  // Malformed
    int cve_2016_4191;  // UAF

    int risk_score;
    char *risk_level;
} ScanResults;

// Check if buffer contains pattern (case insensitive)
int contains_pattern(const char *buffer, size_t len, const char *pattern) {
    size_t pattern_len = strlen(pattern);
    if (pattern_len > len) return 0;

    for (size_t i = 0; i <= len - pattern_len; i++) {
        int match = 1;
        for (size_t j = 0; j < pattern_len; j++) {
            if (tolower(buffer[i+j]) != tolower(pattern[j])) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}

// Count occurrences of pattern
int count_pattern(const char *buffer, size_t len, const char *pattern) {
    int count = 0;
    size_t pattern_len = strlen(pattern);
    if (pattern_len > len) return 0;

    for (size_t i = 0; i <= len - pattern_len; i++) {
        int match = 1;
        for (size_t j = 0; j < pattern_len; j++) {
            if (tolower(buffer[i+j]) != tolower(pattern[j])) {
                match = 0;
                break;
            }
        }
        if (match) {
            count++;
            i += pattern_len - 1;
        }
    }
    return count;
}

void scan_pdf(const char *filename, ScanResults *results) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        return;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size > MAX_FILE_SIZE) {
        printf("[!] File too large: %zu bytes\n", file_size);
        fclose(fp);
        return;
    }

    // Read entire file
    char *buffer = malloc(file_size + 1);
    if (!buffer) {
        perror("malloc");
        fclose(fp);
        return;
    }

    if (fread(buffer, 1, file_size, fp) != file_size) {
        fprintf(stderr, "[!] Read error\n");
    }
    buffer[file_size] = '\0';
    fclose(fp);

    memset(results, 0, sizeof(ScanResults));

    printf("[*] Scanning %s (%zu bytes)...\n\n", filename, file_size);

    // Check PDF signature
    if (file_size < 5 || memcmp(buffer, "%PDF-", 5) != 0) {
        // Check if PDF signature is not at start (polyglot)
        char *pdf_sig = strstr(buffer, "%PDF-");
        if (pdf_sig) {
            printf("⚠️  PDF signature not at file start (offset: %ld)\n", pdf_sig - buffer);
            printf("    Possible polyglot file!\n\n");
            results->risk_score += 20;
        } else {
            printf("[!] Not a valid PDF file\n");
            free(buffer);
            return;
        }
    }

    printf("[*] Detecting vulnerability patterns...\n\n");

    // 1. JavaScript Detection
    results->javascript_count = count_pattern(buffer, file_size, "/javascript");
    if (results->javascript_count > 0) {
        printf("🔴 JavaScript found: %d instance(s)\n", results->javascript_count);
        results->risk_score += 15 * results->javascript_count;

        // Check for util.printf (CVE-2010-1297)
        if (contains_pattern(buffer, file_size, "util.printf")) {
            printf("    🚨 CVE-2010-1297: util.printf() detected\n");
            results->cve_2010_1297 = 1;
            results->risk_score += 30;
        }

        // Check for heap spray patterns
        if (contains_pattern(buffer, file_size, "%u9090") ||
            contains_pattern(buffer, file_size, "unescape")) {
            printf("    🚨 Heap spray pattern detected\n");
            results->risk_score += 25;
        }

        // Check for getAnnots (CVE-2016-4191)
        if (contains_pattern(buffer, file_size, "getAnnots")) {
            printf("    🚨 CVE-2016-4191: getAnnots() UAF pattern\n");
            results->cve_2016_4191 = 1;
            results->risk_score += 30;
        }
    }

    // 2. OpenAction Detection
    if (contains_pattern(buffer, file_size, "/OpenAction")) {
        results->openaction_found = 1;
        printf("🔴 OpenAction auto-execution found\n");
        results->risk_score += 25;
    }

    // 3. Launch Action Detection (CVE-2018-4990)
    results->launch_action_count = count_pattern(buffer, file_size, "/Launch");
    if (results->launch_action_count > 0) {
        printf("🔴 Launch action found: %d instance(s)\n", results->launch_action_count);
        results->cve_2018_4990 = 1;
        results->risk_score += 35;

        // Check for command execution
        if (contains_pattern(buffer, file_size, "cmd.exe") ||
            contains_pattern(buffer, file_size, "powershell") ||
            contains_pattern(buffer, file_size, "/bin/sh")) {
            printf("    🚨 Command execution detected!\n");
            results->risk_score += 40;
        }
    }

    // 4. Embedded Files
    if (contains_pattern(buffer, file_size, "/EmbeddedFile") ||
        contains_pattern(buffer, file_size, "/Filespec")) {
        results->embedded_files = 1;
        printf("🟡 Embedded files detected\n");
        results->risk_score += 10;
    }

    // 5. Flash/SWF Content (CVE-2011-0611)
    if (contains_pattern(buffer, file_size, "/RichMedia") ||
        contains_pattern(buffer, file_size, "FWS") ||
        contains_pattern(buffer, file_size, "CWS")) {
        results->flash_content = 1;
        results->cve_2011_0611 = 1;
        printf("🔴 Flash/SWF content detected\n");
        printf("    🚨 CVE-2011-0611: Flash exploitation risk\n");
        results->risk_score += 30;
    }

    // 6. XFA Forms (CVE-2017-3014)
    if (contains_pattern(buffer, file_size, "/XFA")) {
        results->xfa_forms = 1;
        printf("🟡 XFA forms detected\n");
        results->risk_score += 15;

        if (contains_pattern(buffer, file_size, "<textEdit") &&
            contains_pattern(buffer, file_size, "<button")) {
            printf("    🚨 CVE-2017-3014: Type confusion pattern\n");
            results->risk_score += 25;
        }
    }

    // 7. JBIG2Decode (CVE-2009-0927)
    if (contains_pattern(buffer, file_size, "/JBIG2Decode")) {
        results->cve_2009_0927 = 1;
        printf("🟡 JBIG2Decode filter detected\n");
        printf("    🚨 CVE-2009-0927: Potential integer overflow\n");
        results->risk_score += 20;
    }

    // 8. CCITTFaxDecode (CVE-2010-0188)
    if (contains_pattern(buffer, file_size, "/CCITTFaxDecode")) {
        results->cve_2010_0188 = 1;
        printf("🟡 CCITTFaxDecode filter detected\n");
        printf("    🚨 CVE-2010-0188: Potential integer overflow\n");
        results->risk_score += 20;
    }

    // 9. Suspicious Filters
    if (contains_pattern(buffer, file_size, "/ASCIIHexDecode") ||
        contains_pattern(buffer, file_size, "/ASCII85Decode") ||
        contains_pattern(buffer, file_size, "/RunLengthDecode")) {
        results->suspicious_filters = 1;
        printf("🟡 Unusual filters detected\n");
        results->risk_score += 5;
    }

    // 10. Malformed Objects (CVE-2013-3346)
    if (contains_pattern(buffer, file_size, "/ObjStm")) {
        printf("🟡 Object streams detected\n");

        // Check for extreme values (integer overflow attempts)
        if (contains_pattern(buffer, file_size, "0xFFFFFFFF") ||
            contains_pattern(buffer, file_size, "0x7FFFFFFF") ||
            contains_pattern(buffer, file_size, "4294967295")) {
            results->extreme_values = 1;
            results->cve_2013_3346 = 1;
            printf("    🚨 CVE-2013-3346: Extreme values detected\n");
            results->risk_score += 30;
        }
    }

    // 11. URI Actions
    results->uri_actions = count_pattern(buffer, file_size, "/URI");
    if (results->uri_actions > 0) {
        printf("🟡 URI actions found: %d\n", results->uri_actions);
        results->risk_score += 5 * results->uri_actions;
    }

    // 12. Additional Actions (AA)
    if (contains_pattern(buffer, file_size, "/AA")) {
        results->aa_actions = 1;
        printf("🟡 Additional Actions (AA) found\n");
        results->risk_score += 10;
    }

    // 13. Check for obfuscation
    int hex_strings = count_pattern(buffer, file_size, "<");
    if (hex_strings > 100) {
        printf("🟡 High number of hex strings: %d (possible obfuscation)\n", hex_strings);
        results->risk_score += 10;
    }

    // Determine risk level
    if (results->risk_score >= 100) {
        results->risk_level = "CRITICAL";
    } else if (results->risk_score >= 70) {
        results->risk_level = "HIGH";
    } else if (results->risk_score >= 40) {
        results->risk_level = "MEDIUM";
    } else if (results->risk_score >= 20) {
        results->risk_level = "LOW";
    } else {
        results->risk_level = "MINIMAL";
    }

    free(buffer);
}

void print_report(ScanResults *results) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║            PDF VULNERABILITY SCAN RESULTS                   ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    printf("RISK ASSESSMENT:\n");
    printf("─────────────────────────────────────────────────────────────\n");
    printf("  Risk Score:  %d / 200\n", results->risk_score);
    printf("  Risk Level:  %s\n\n", results->risk_level);

    printf("DETECTED CVEs:\n");
    printf("─────────────────────────────────────────────────────────────\n");

    int cve_count = 0;
    if (results->cve_2010_1297) {
        printf("  ✗ CVE-2010-1297: util.printf() buffer overflow\n");
        cve_count++;
    }
    if (results->cve_2013_0640) {
        printf("  ✗ CVE-2013-0640: JavaScript API exploitation\n");
        cve_count++;
    }
    if (results->cve_2018_4990) {
        printf("  ✗ CVE-2018-4990: Launch action command injection\n");
        cve_count++;
    }
    if (results->cve_2009_0927) {
        printf("  ✗ CVE-2009-0927: JBIG2Decode integer overflow\n");
        cve_count++;
    }
    if (results->cve_2010_0188) {
        printf("  ✗ CVE-2010-0188: LibTIFF integer overflow\n");
        cve_count++;
    }
    if (results->cve_2011_0611) {
        printf("  ✗ CVE-2011-0611: Flash/SWF exploitation\n");
        cve_count++;
    }
    if (results->cve_2013_3346) {
        printf("  ✗ CVE-2013-3346: Malformed object streams\n");
        cve_count++;
    }
    if (results->cve_2016_4191) {
        printf("  ✗ CVE-2016-4191: Use-after-free in annotations\n");
        cve_count++;
    }

    if (cve_count == 0) {
        printf("  ✓ No known CVE patterns detected\n");
    }
    printf("\n");

    printf("RECOMMENDATIONS:\n");
    printf("─────────────────────────────────────────────────────────────\n");

    if (results->risk_score >= 100) {
        printf("  🚨 CRITICAL: DO NOT OPEN THIS FILE\n");
        printf("  • Quarantine immediately\n");
        printf("  • Report to security team\n");
        printf("  • Analyze in isolated sandbox only\n");
    } else if (results->risk_score >= 70) {
        printf("  ⚠️  HIGH RISK: Exercise extreme caution\n");
        printf("  • Open only in sandboxed environment\n");
        printf("  • Disable JavaScript in PDF reader\n");
        printf("  • Verify source before opening\n");
    } else if (results->risk_score >= 40) {
        printf("  ⚠️  MEDIUM RISK: Caution advised\n");
        printf("  • Use updated PDF reader\n");
        printf("  • Disable JavaScript\n");
        printf("  • Scan with antivirus\n");
    } else if (results->risk_score >= 20) {
        printf("  ℹ️  LOW RISK: Minor concerns\n");
        printf("  • Standard precautions recommended\n");
        printf("  • Keep software updated\n");
    } else {
        printf("  ✓ MINIMAL RISK: File appears clean\n");
        printf("  • Standard security practices apply\n");
    }

    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("PDF Vulnerability Scanner v%s\n\n", VERSION);
        printf("Scans PDFs for known vulnerability patterns and exploits.\n\n");
        printf("Usage: %s <pdf_file> [pdf_file2] ...\n\n", argv[0]);
        printf("Detects:\n");
        printf("  • JavaScript exploits (CVE-2010-1297, CVE-2013-0640)\n");
        printf("  • Launch action injection (CVE-2018-4990)\n");
        printf("  • Integer overflows (CVE-2009-0927, CVE-2010-0188)\n");
        printf("  • Flash exploitation (CVE-2011-0611)\n");
        printf("  • Malformed objects (CVE-2013-3346)\n");
        printf("  • Use-after-free (CVE-2016-4191)\n");
        printf("  • OpenAction auto-execution\n");
        printf("  • Embedded malicious files\n");
        printf("  • Suspicious structure and obfuscation\n\n");
        printf("Example:\n");
        printf("  %s suspicious.pdf\n", argv[0]);
        printf("  %s *.pdf\n\n", argv[0]);
        return 1;
    }

    printf("[*] PDF Vulnerability Scanner v%s\n", VERSION);
    printf("[*] Scanning %d file(s)...\n\n", argc - 1);

    for (int i = 1; i < argc; i++) {
        ScanResults results;
        scan_pdf(argv[i], &results);
        print_report(&results);

        if (i < argc - 1) {
            printf("\n");
        }
    }

    return 0;
}
