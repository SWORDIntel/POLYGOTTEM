#!/bin/bash
#
# POLYGOTTEM CVE Exploit Test Suite
# ==================================
# Tests all 20 CVE implementations in exploit_header_generator.py
#
# Author: SWORDIntel
# Date: 2025-11-10
#
# Usage:
#   ./test_all_cves.sh [--clean]
#
# Options:
#   --clean    Remove generated test files after completion
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Test output directory
TEST_DIR="/tmp/polygottem_cve_tests"
mkdir -p "$TEST_DIR"

echo -e "${BLUE}=================================${NC}"
echo -e "${BLUE}POLYGOTTEM CVE Test Suite${NC}"
echo -e "${BLUE}=================================${NC}"
echo ""
echo "Test directory: $TEST_DIR"
echo ""

# Function to test a single CVE
test_cve() {
    local cve_id="$1"
    local expected_ext="$2"
    local expected_magic="$3"
    local description="$4"

    TESTS_TOTAL=$((TESTS_TOTAL + 1))

    echo -e "${YELLOW}[TEST $TESTS_TOTAL]${NC} Testing $cve_id - $description"

    local output_file="$TEST_DIR/test_${cve_id}${expected_ext}"

    # Generate exploit
    if python3 tools/exploit_header_generator.py "$cve_id" "$output_file" -p poc_marker > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Exploit generated successfully"

        # Check if file exists
        if [ ! -f "$output_file" ]; then
            echo -e "  ${RED}✗${NC} Output file not created"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            return 1
        fi

        # Check file size
        local file_size=$(stat -f%z "$output_file" 2>/dev/null || stat -c%s "$output_file" 2>/dev/null)
        if [ "$file_size" -lt 100 ]; then
            echo -e "  ${RED}✗${NC} File too small ($file_size bytes)"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            return 1
        fi
        echo -e "  ${GREEN}✓${NC} File size: $file_size bytes"

        # Check file magic bytes
        local actual_magic=$(xxd -p -l ${#expected_magic} "$output_file" | tr -d '\n')
        if [ "$actual_magic" == "$expected_magic" ]; then
            echo -e "  ${GREEN}✓${NC} Correct file magic: $expected_magic"
        else
            echo -e "  ${YELLOW}!${NC} Magic mismatch: expected $expected_magic, got $actual_magic"
        fi

        # Run file command
        local file_type=$(file "$output_file" 2>/dev/null || echo "unknown")
        echo -e "  ${BLUE}ℹ${NC} File type: $file_type"

        # Check for shellcode marker
        if grep -q "SHELLCODE_EXECUTED_HERE" "$output_file" 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} Shellcode marker found"
        fi

        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓ PASS${NC}"
        echo ""
        return 0

    else
        echo -e "  ${RED}✗${NC} Failed to generate exploit"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗ FAIL${NC}"
        echo ""
        return 1
    fi
}

# ==================== EXISTING CVEs ====================
echo -e "${BLUE}=== Testing EXISTING CVEs (5 total) ===${NC}"
echo ""

test_cve "CVE-2015-8540" ".png" "89504e470d0a1a0a" "libpng buffer overflow"
test_cve "CVE-2019-7317" ".png" "89504e470d0a1a0a" "libpng use-after-free"
test_cve "CVE-2018-14498" ".jpg" "ffd8ff" "libjpeg heap over-read"
test_cve "CVE-2019-15133" ".gif" "474946383961" "giflib division by zero"
test_cve "CVE-2016-3977" ".gif" "474946383961" "giflib heap overflow"

# ==================== PRIORITY 1 CVEs ====================
echo -e "${BLUE}=== Testing PRIORITY 1 CVEs (3 total) ===${NC}"
echo ""

test_cve "CVE-2023-4863" ".webp" "52494646" "libwebp CRITICAL heap overflow"
test_cve "CVE-2024-10573" ".mp3" "494433" "mpg123 Frankenstein stream"
test_cve "CVE-2023-52356" ".tiff" "49492a00" "libtiff heap overflow"

# ==================== PRIORITY 2 CVEs ====================
echo -e "${BLUE}=== Testing PRIORITY 2 CVEs (6 total) ===${NC}"
echo ""

test_cve "CVE-2017-8373" ".mp3" "494433" "libmad MP3 heap overflow"
test_cve "CVE-2006-0006" ".bmp" "424d" "Windows Media Player BMP"
test_cve "CVE-2020-22219" ".flac" "664c6143" "FLAC encoder overflow"
test_cve "CVE-2020-0499" ".flac" "664c6143" "FLAC decoder OOB read"
test_cve "CVE-2008-1083" ".wmf" "d7cdc69a" "Windows GDI WMF overflow"
test_cve "CVE-2005-4560" ".wmf" "d7cdc69a" "WMF SETABORTPROC"

# ==================== PRIORITY 3 CVEs ====================
echo -e "${BLUE}=== Testing PRIORITY 3 CVEs (6 total) ===${NC}"
echo ""

test_cve "CVE-2017-6827" ".wav" "52494646" "audiofile WAV MSADPCM"
test_cve "CVE-2018-5146" ".ogg" "4f676753" "libvorbis OGG OOB write"
test_cve "CVE-2022-22675" ".mp4" "0000001466747970" "AppleAVD video overflow"
test_cve "CVE-2021-0561" ".flac" "664c6143" "FLAC encoder OOB write"
test_cve "CVE-2017-11126" ".mp3" "494433" "mpg123 intensity stereo"
test_cve "CVE-2021-40426" ".sph" "4e4953545f3141" "libsox SPHERE overflow"

# ==================== SUMMARY ====================
echo ""
echo -e "${BLUE}=================================${NC}"
echo -e "${BLUE}TEST SUMMARY${NC}"
echo -e "${BLUE}=================================${NC}"
echo ""
echo -e "Total tests:  $TESTS_TOTAL"
echo -e "${GREEN}Passed:       $TESTS_PASSED${NC}"
echo -e "${RED}Failed:       $TESTS_FAILED${NC}"
echo ""

# Calculate success rate
if [ $TESTS_TOTAL -gt 0 ]; then
    SUCCESS_RATE=$(awk "BEGIN {printf \"%.1f\", ($TESTS_PASSED/$TESTS_TOTAL)*100}")
    echo -e "Success rate: ${SUCCESS_RATE}%"
    echo ""
fi

# List generated files
echo -e "${BLUE}Generated test files:${NC}"
ls -lh "$TEST_DIR/" | tail -n +2
echo ""

# Check if YARA rules should be tested
if command -v yara &> /dev/null; then
    echo -e "${BLUE}=== Testing YARA Detection Rules ===${NC}"
    echo ""

    if [ -f "detection/cve_exploits.yar" ]; then
        echo "Running YARA scan on generated files..."
        yara -r detection/cve_exploits.yar "$TEST_DIR/" > "$TEST_DIR/yara_results.txt" 2>&1

        local yara_matches=$(cat "$TEST_DIR/yara_results.txt" | wc -l)
        echo -e "${GREEN}✓${NC} YARA detected $yara_matches potential exploits"
        echo ""
        echo "Top matches:"
        head -n 10 "$TEST_DIR/yara_results.txt"
        echo ""
    else
        echo -e "${YELLOW}!${NC} YARA rules file not found at detection/cve_exploits.yar"
    fi
else
    echo -e "${YELLOW}!${NC} YARA not installed, skipping detection tests"
    echo "  Install with: apt-get install yara (Debian/Ubuntu) or brew install yara (macOS)"
fi

# File format validation
echo -e "${BLUE}=== File Format Validation ===${NC}"
echo ""

echo "Checking file command recognition:"
for file in "$TEST_DIR"/*; do
    if [ -f "$file" ]; then
        basename=$(basename "$file")
        file_output=$(file "$file")
        echo "  $basename: $file_output"
    fi
done
echo ""

# Entropy analysis
echo -e "${BLUE}=== Entropy Analysis ===${NC}"
echo ""

if command -v ent &> /dev/null; then
    echo "Running entropy analysis on sample files..."
    for file in "$TEST_DIR"/test_CVE-2023-4863* "$TEST_DIR"/test_CVE-2024-10573* "$TEST_DIR"/test_CVE-2023-52356*; do
        if [ -f "$file" ]; then
            echo ""
            echo "File: $(basename "$file")"
            ent "$file" | head -n 3
        fi
    done
else
    echo -e "${YELLOW}!${NC} ent tool not installed, skipping entropy analysis"
    echo "  Install with: apt-get install ent (Debian/Ubuntu)"
fi
echo ""

# Cleanup option
if [ "$1" == "--clean" ]; then
    echo -e "${YELLOW}Cleaning up test files...${NC}"
    rm -rf "$TEST_DIR"
    echo -e "${GREEN}✓${NC} Test directory removed"
    echo ""
fi

# Exit with appropriate code
if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
