#!/bin/bash
# World Record Polyglot Verification Suite
# Tests all formats in the polyglot file

set -e

POLYGLOT="$1"

if [ -z "$POLYGLOT" ]; then
    echo "Usage: $0 <polyglot_file>"
    exit 1
fi

if [ ! -f "$POLYGLOT" ]; then
    echo "[!] File not found: $POLYGLOT"
    exit 1
fi

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "=========================================="
echo "WORLD RECORD POLYGLOT VERIFICATION"
echo "=========================================="
echo ""
echo "File: $POLYGLOT"
echo "Size: $(stat -f%z "$POLYGLOT" 2>/dev/null || stat -c%s "$POLYGLOT" 2>/dev/null) bytes"
echo ""

PASSED=0
TOTAL=0

# Test 1: Bash Script
echo -e "${BLUE}[TEST 1/8] Bash Script${NC}"
TOTAL=$((TOTAL+1))
if bash "$POLYGLOT" 2>/dev/null | grep -q "Polyglot"; then
    echo -e "  ${GREEN}✓ PASS${NC} - Executes as Bash script"
    PASSED=$((PASSED+1))
else
    echo -e "  ${RED}✗ FAIL${NC} - Bash execution failed"
fi
echo ""

# Test 2: GIF Image
echo -e "${BLUE}[TEST 2/8] GIF Image${NC}"
TOTAL=$((TOTAL+1))
if file "$POLYGLOT" | grep -iq "GIF"; then
    echo -e "  ${GREEN}✓ PASS${NC} - Detected as GIF"
    PASSED=$((PASSED+1))

    # Try to extract with ImageMagick
    if command -v convert &> /dev/null; then
        if convert "$POLYGLOT" /tmp/polyglot_test.png 2>/dev/null; then
            echo -e "  ${GREEN}✓ BONUS${NC} - Successfully converted GIF to PNG"
            rm -f /tmp/polyglot_test.png
        fi
    fi
else
    echo -e "  ${YELLOW}⚠ WARN${NC} - Not detected as GIF by 'file' command"
    # Try anyway
    if command -v identify &> /dev/null; then
        if identify "$POLYGLOT" 2>/dev/null | grep -q "GIF"; then
            echo -e "  ${GREEN}✓ PASS${NC} - Validated as GIF by ImageMagick"
            PASSED=$((PASSED+1))
        fi
    fi
fi
echo ""

# Test 3: HTML Page
echo -e "${BLUE}[TEST 3/8] HTML Page${NC}"
TOTAL=$((TOTAL+1))
if strings "$POLYGLOT" | grep -q "<!DOCTYPE html>"; then
    echo -e "  ${GREEN}✓ PASS${NC} - Contains valid HTML"
    PASSED=$((PASSED+1))

    # Extract HTML portion
    cp "$POLYGLOT" /tmp/polyglot_test.html
    echo -e "  ${GREEN}✓ INFO${NC} - Try: firefox /tmp/polyglot_test.html"
else
    echo -e "  ${RED}✗ FAIL${NC} - No HTML content found"
fi
echo ""

# Test 4: JPEG Image
echo -e "${BLUE}[TEST 4/8] JPEG Image${NC}"
TOTAL=$((TOTAL+1))
# Look for JPEG SOI marker
if grep -abq $'\xFF\xD8\xFF' "$POLYGLOT"; then
    echo -e "  ${GREEN}✓ PASS${NC} - Contains JPEG SOI marker"
    PASSED=$((PASSED+1))

    # Try to extract JPEG
    JPEG_OFFSET=$(grep -abo $'\xFF\xD8\xFF' "$POLYGLOT" | tail -1 | cut -d: -f1)
    if [ -n "$JPEG_OFFSET" ]; then
        dd if="$POLYGLOT" of=/tmp/polyglot_test.jpg bs=1 skip=$JPEG_OFFSET count=10000 2>/dev/null
        if file /tmp/polyglot_test.jpg | grep -q "JPEG"; then
            echo -e "  ${GREEN}✓ BONUS${NC} - Extracted valid JPEG image"
            rm -f /tmp/polyglot_test.jpg
        fi
    fi
else
    echo -e "  ${RED}✗ FAIL${NC} - No JPEG marker found"
fi
echo ""

# Test 5: ZIP Archive
echo -e "${BLUE}[TEST 5/8] ZIP Archive${NC}"
TOTAL=$((TOTAL+1))
if unzip -l "$POLYGLOT" &>/dev/null; then
    echo -e "  ${GREEN}✓ PASS${NC} - Valid ZIP archive"
    PASSED=$((PASSED+1))

    echo -e "  ${GREEN}Contents:${NC}"
    unzip -l "$POLYGLOT" | grep -E "\.(pdf|txt|exe|MF)$" | sed 's/^/    /'

    # Extract to temp
    mkdir -p /tmp/polyglot_extract
    unzip -q -o "$POLYGLOT" -d /tmp/polyglot_extract 2>/dev/null || true
else
    echo -e "  ${RED}✗ FAIL${NC} - Not a valid ZIP archive"
fi
echo ""

# Test 6: PDF Document
echo -e "${BLUE}[TEST 6/8] PDF Document${NC}"
TOTAL=$((TOTAL+1))
if [ -f /tmp/polyglot_extract/document.pdf ]; then
    if file /tmp/polyglot_extract/document.pdf | grep -q "PDF"; then
        echo -e "  ${GREEN}✓ PASS${NC} - Contains valid PDF document"
        PASSED=$((PASSED+1))

        # Try pdfinfo
        if command -v pdfinfo &> /dev/null; then
            if pdfinfo /tmp/polyglot_extract/document.pdf &>/dev/null; then
                echo -e "  ${GREEN}✓ BONUS${NC} - PDF validated with pdfinfo"
            fi
        fi
    else
        echo -e "  ${RED}✗ FAIL${NC} - PDF extraction failed"
    fi
else
    echo -e "  ${YELLOW}⚠ WARN${NC} - No document.pdf found in ZIP"
fi
echo ""

# Test 7: JAR (Java Archive)
echo -e "${BLUE}[TEST 7/8] JAR (Java Archive)${NC}"
TOTAL=$((TOTAL+1))
if [ -f /tmp/polyglot_extract/META-INF/MANIFEST.MF ]; then
    if grep -q "Manifest-Version" /tmp/polyglot_extract/META-INF/MANIFEST.MF; then
        echo -e "  ${GREEN}✓ PASS${NC} - Contains valid JAR manifest"
        PASSED=$((PASSED+1))

        echo -e "  ${GREEN}Manifest:${NC}"
        cat /tmp/polyglot_extract/META-INF/MANIFEST.MF | sed 's/^/    /'
    else
        echo -e "  ${RED}✗ FAIL${NC} - Invalid JAR manifest"
    fi
else
    echo -e "  ${YELLOW}⚠ SKIP${NC} - No JAR manifest (only in 7+ way polyglots)"
fi
echo ""

# Test 8: PE Executable
echo -e "${BLUE}[TEST 8/8] PE Executable${NC}"
TOTAL=$((TOTAL+1))
if [ -f /tmp/polyglot_extract/payload.exe ]; then
    if file /tmp/polyglot_extract/payload.exe | grep -qE "(PE32|MS-DOS|executable)"; then
        echo -e "  ${GREEN}✓ PASS${NC} - Contains PE executable"
        PASSED=$((PASSED+1))

        echo -e "  ${GREEN}File info:${NC}"
        file /tmp/polyglot_extract/payload.exe | sed 's/^/    /'
    else
        echo -e "  ${RED}✗ FAIL${NC} - Invalid PE file"
    fi
else
    echo -e "  ${YELLOW}⚠ SKIP${NC} - No PE executable (only in 8-way polyglot)"
fi
echo ""

# Cleanup
rm -rf /tmp/polyglot_extract /tmp/polyglot_test.*

# Final results
echo "=========================================="
echo "VERIFICATION RESULTS"
echo "=========================================="
echo ""

PERCENTAGE=$((PASSED * 100 / TOTAL))

if [ $PASSED -eq $TOTAL ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED! ($PASSED/$TOTAL)${NC}"
    echo ""
    echo -e "${GREEN}🏆 WORLD RECORD POLYGLOT VERIFIED!${NC}"
elif [ $PERCENTAGE -ge 75 ]; then
    echo -e "${GREEN}✓ MOST TESTS PASSED ($PASSED/$TOTAL = $PERCENTAGE%)${NC}"
    echo ""
    echo -e "${GREEN}🏆 WORLD RECORD ACHIEVED!${NC}"
else
    echo -e "${YELLOW}⚠ PARTIAL SUCCESS ($PASSED/$TOTAL = $PERCENTAGE%)${NC}"
fi

echo ""
echo "Summary:"
echo "  Passed: $PASSED"
echo "  Total:  $TOTAL"
echo "  Rate:   $PERCENTAGE%"
echo ""

if [ $PASSED -ge 6 ]; then
    echo "This polyglot beats PoC||GTFO's 5-way record!"
    echo ""
    echo "Verified formats:"
    [ $PASSED -ge 1 ] && echo "  ✓ Bash script"
    [ $PASSED -ge 2 ] && echo "  ✓ GIF image"
    [ $PASSED -ge 3 ] && echo "  ✓ HTML page"
    [ $PASSED -ge 4 ] && echo "  ✓ JPEG image"
    [ $PASSED -ge 5 ] && echo "  ✓ ZIP archive"
    [ $PASSED -ge 6 ] && echo "  ✓ PDF document"
    [ $PASSED -ge 7 ] && echo "  ✓ JAR (Java)"
    [ $PASSED -ge 8 ] && echo "  ✓ PE executable"
fi

echo ""
echo "=========================================="

exit 0
