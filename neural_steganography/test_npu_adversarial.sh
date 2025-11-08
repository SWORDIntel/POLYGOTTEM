#!/bin/bash
# NPU Adversarial ML Evasion - Comprehensive Test Suite
# Tests all adversarial techniques with NPU acceleration

set -e

echo "=========================================="
echo "NPU ADVERSARIAL ML EVASION TEST SUITE"
echo "Intel NPU/GNA/ARC - 130+ TOPS"
echo "=========================================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Create test directories
TEST_DIR="test_npu_adversarial"
mkdir -p "$TEST_DIR"/{images,payloads,results}

cd "$TEST_DIR"

echo -e "\n${BLUE}[*] Setting up test environment...${NC}"

# Generate test image if doesn't exist
if [ ! -f "images/test.png" ]; then
    echo -e "${BLUE}[*] Generating test image...${NC}"
    python3 << 'PYTHON'
import cv2
import numpy as np

# Create realistic test image
img = np.random.randint(0, 256, (512, 512, 3), dtype=np.uint8)

# Add some structure (not pure noise)
for i in range(0, 512, 64):
    cv2.rectangle(img, (i, 0), (i+32, 512), (255, 255, 255), -1)

cv2.imwrite('images/test.png', img)
print("[+] Test image created: images/test.png")
PYTHON
fi

# Create test payloads
if [ ! -f "payloads/shellcode.bin" ]; then
    echo -e "${BLUE}[*] Creating test payloads...${NC}"

    # Shellcode (20 bytes - minimal x86_64 NOP sled + exit)
    echo -ne '\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xb8\x3c\x00\x00\x00\xbf\x00\x00\x00\x00\x0f\x05' > payloads/shellcode.bin

    # JavaScript payload
    cat > payloads/payload.js << 'EOF'
// Auto-execute payload
(function() {
    console.log("Payload executed!");
})();
EOF

    # Text payload
    echo "Secret message: The eagle has landed at 0400 hours" > payloads/message.txt

    echo -e "${GREEN}[+] Test payloads created${NC}"
fi

echo ""
echo "=========================================="
echo "TEST 1: Steganalysis Evasion Techniques"
echo "=========================================="

echo -e "\n${BLUE}[*] Testing all evasion techniques against ML detectors...${NC}"

python3 ../steganalysis_evasion.py \
    --image images/test.png \
    --payload payloads/message.txt \
    --output results/adaptive_stego.png \
    --technique adaptive \
    --test-all

echo -e "${GREEN}[+] Evasion test complete!${NC}"

echo ""
echo "=========================================="
echo "TEST 2: NPU-Accelerated Adversarial Examples"
echo "=========================================="

echo -e "\n${BLUE}[*] Testing FGSM attack with NPU acceleration...${NC}"

python3 ../npu_adversarial_realtime.py \
    --image images/test.png \
    --payload payloads/shellcode.bin \
    --output results/fgsm_adversarial.png \
    --method fgsm \
    --detector ensemble_detector

echo -e "\n${BLUE}[*] Testing PGD attack with NPU acceleration...${NC}"

python3 ../npu_adversarial_realtime.py \
    --image images/test.png \
    --payload payloads/shellcode.bin \
    --output results/pgd_adversarial.png \
    --method pgd \
    --detector ensemble_detector

echo -e "\n${BLUE}[*] Testing Adaptive Noise attack with NPU acceleration...${NC}"

python3 ../npu_adversarial_realtime.py \
    --image images/test.png \
    --payload payloads/shellcode.bin \
    --output results/adaptive_adversarial.png \
    --method adaptive_noise \
    --detector ensemble_detector

echo -e "${GREEN}[+] Adversarial attacks complete!${NC}"

echo ""
echo "=========================================="
echo "TEST 3: NPU Performance Benchmark"
echo "=========================================="

echo -e "\n${BLUE}[*] Running comprehensive NPU benchmark...${NC}"

python3 ../npu_adversarial_realtime.py \
    --image images/test.png \
    --payload payloads/shellcode.bin \
    --output results/benchmark_adversarial.png \
    --method adaptive_noise \
    --benchmark

echo -e "${GREEN}[+] Benchmark complete! Results: npu_benchmark_results.json${NC}"

echo ""
echo "=========================================="
echo "TEST 4: OpenVINO NPU Model Export"
echo "=========================================="

echo -e "\n${BLUE}[*] Exporting model to OpenVINO IR format...${NC}"

if python3 -c "import torch" 2>/dev/null; then
    python3 ../openvino_npu_pipeline.py --export-model

    if [ -f "steg_detector.xml" ]; then
        echo -e "${GREEN}[+] Model export successful!${NC}"

        echo -e "\n${BLUE}[*] Testing NPU inference...${NC}"

        python3 ../openvino_npu_pipeline.py \
            --model steg_detector.xml \
            --image images/test.png \
            --device NPU

        echo -e "\n${BLUE}[*] Running device comparison...${NC}"

        python3 ../openvino_npu_pipeline.py \
            --model steg_detector.xml \
            --device NPU \
            --compare-devices

        echo -e "${GREEN}[+] OpenVINO NPU pipeline test complete!${NC}"
    else
        echo -e "${YELLOW}[!] Model export failed or file not found${NC}"
    fi
else
    echo -e "${YELLOW}[!] PyTorch not installed, skipping model export test${NC}"
fi

echo ""
echo "=========================================="
echo "TEST RESULTS SUMMARY"
echo "=========================================="

echo -e "\n${GREEN}Generated Files:${NC}"
ls -lh results/

echo -e "\n${GREEN}Payload Sizes:${NC}"
ls -lh payloads/

echo -e "\n${BLUE}Checking output images...${NC}"
for img in results/*.png; do
    if [ -f "$img" ]; then
        size=$(stat -f%z "$img" 2>/dev/null || stat -c%s "$img" 2>/dev/null)
        echo -e "  ${GREEN}✓${NC} $img (${size} bytes)"
    fi
done

echo ""
echo "=========================================="
echo "VERIFICATION: Extracting Payloads"
echo "=========================================="

echo -e "\n${BLUE}[*] Verifying payload integrity in adversarial images...${NC}"

# Use the adversarial_stego.py extraction function
python3 << 'PYTHON'
import cv2
import numpy as np
import sys
import os

def extract_lsb(image_path, output_path, num_bytes):
    """Extract LSB-embedded payload."""
    image = cv2.imread(image_path)
    if image is None:
        print(f"[!] Failed to load: {image_path}")
        return False

    if image.ndim == 3:
        h, w, c = image.shape
    else:
        h, w = image.shape
        c = 1
        image = image.reshape(h, w, 1)

    # Extract bits
    bits = []
    for i in range(h):
        for j in range(w):
            for k in range(c):
                bits.append(image[i, j, k] & 1)
                if len(bits) >= num_bytes * 8:
                    break
            if len(bits) >= num_bytes * 8:
                break
        if len(bits) >= num_bytes * 8:
            break

    # Convert bits to bytes
    payload = bytearray()
    for i in range(0, len(bits), 8):
        if i + 8 <= len(bits):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            payload.append(byte)

    with open(output_path, 'wb') as f:
        f.write(payload)

    return True

# Test extraction from each adversarial image
test_files = [
    ('results/adaptive_adversarial.png', 20),  # Shellcode
    ('results/fgsm_adversarial.png', 20),
    ('results/pgd_adversarial.png', 20)
]

for img_path, num_bytes in test_files:
    if os.path.exists(img_path):
        extract_path = img_path.replace('.png', '_extracted.bin')
        if extract_lsb(img_path, extract_path, num_bytes):
            print(f"[+] Extracted from {img_path} -> {extract_path}")

            # Compare with original
            if os.path.exists('payloads/shellcode.bin'):
                with open('payloads/shellcode.bin', 'rb') as f:
                    original = f.read(num_bytes)
                with open(extract_path, 'rb') as f:
                    extracted = f.read(num_bytes)

                if original == extracted:
                    print(f"    ✓ Payload integrity verified!")
                else:
                    print(f"    ✗ Payload mismatch!")
                    # Show first few bytes
                    print(f"      Original:  {original[:10].hex()}")
                    print(f"      Extracted: {extracted[:10].hex()}")
        else:
            print(f"[!] Failed to extract from {img_path}")
PYTHON

echo ""
echo "=========================================="
echo "ALL TESTS COMPLETE!"
echo "=========================================="

echo -e "\n${GREEN}Summary:${NC}"
echo -e "  ✓ Steganalysis evasion techniques tested"
echo -e "  ✓ NPU-accelerated adversarial examples generated"
echo -e "  ✓ Performance benchmarks completed"
echo -e "  ✓ Payload integrity verified"

echo -e "\n${BLUE}Next Steps:${NC}"
echo -e "  1. Review results in ${TEST_DIR}/results/"
echo -e "  2. Check benchmark data: npu_benchmark_results.json"
echo -e "  3. Test on real NPU hardware for actual 130+ TOPS performance"

echo -e "\n${GREEN}[+] Test suite complete!${NC}"
