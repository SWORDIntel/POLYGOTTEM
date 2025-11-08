# Makefile for APT TeamTNT Polyglot Tools
# ========================================
# VX Underground Publication Package
#
# Author: SWORDIntel
# Date: 2025-11-08
# Attribution: APT TeamTNT

CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
TARGETS = polyglot_embed polyglot_extract

.PHONY: all clean test demo install

all: $(TARGETS)
	@echo ""
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║  APT TeamTNT Polyglot Tools - Build Complete          ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Built targets:"
	@ls -lh $(TARGETS)
	@echo ""
	@echo "Run 'make demo' for a demonstration"
	@echo ""

polyglot_embed: polyglot_embed.c
	$(CC) $(CFLAGS) -o $@ $<

polyglot_extract: polyglot_extract.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)
	rm -f test_image.gif infected_meme.gif extracted_payload.bin
	rm -f *.o *~ core

# Create a minimal test GIF
test_image.gif:
	@echo "Creating minimal test GIF..."
	@python3 -c "open('test_image.gif','wb').write(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b')"
	@echo "Created test_image.gif (1x1 transparent GIF)"

# Run demonstration
demo: all test_image.gif
	@echo ""
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║           APT TeamTNT Polyglot Demonstration           ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "[Step 1/4] Embedding Albanian virus meme into image..."
	@echo ""
	./polyglot_embed test_image.gif albanian_virus.sh infected_meme.gif 9e0a61200d
	@echo ""
	@echo "[Step 2/4] Verifying image file..."
	@file infected_meme.gif
	@echo ""
	@echo "[Step 3/4] Extracting payload..."
	@echo ""
	./polyglot_extract infected_meme.gif extracted_payload.bin 9e0a61200d
	@echo ""
	@echo "[Step 4/4] Making payload executable and running it..."
	@echo ""
	@chmod +x extracted_payload.bin
	@bash extracted_payload.bin
	@echo ""
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║              Demonstration Complete!                   ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "The Albanian virus payload was successfully:"
	@echo "  1. Embedded into a GIF image"
	@echo "  2. Encrypted with XOR"
	@echo "  3. Extracted and decrypted"
	@echo "  4. Executed to display the meme"
	@echo ""
	@echo "In a real attack:"
	@echo "  - Images would be distributed on social media"
	@echo "  - Auto-execution via .desktop handlers"
	@echo "  - Actual malware instead of memes"
	@echo ""

# Test suite
test: all test_image.gif
	@echo "Running tests..."
	@echo ""
	@echo "Test 1: Embed with single-byte key"
	./polyglot_embed test_image.gif albanian_virus.sh test1.gif 9e
	./polyglot_extract test1.gif test1_out.bin 9e
	@diff -q albanian_virus.sh test1_out.bin && echo "✓ Test 1 PASSED" || echo "✗ Test 1 FAILED"
	@echo ""
	@echo "Test 2: Embed with multi-byte key"
	./polyglot_embed test_image.gif albanian_virus.sh test2.gif 9e0a61200d
	./polyglot_extract test2.gif test2_out.bin 9e0a61200d
	@diff -q albanian_virus.sh test2_out.bin && echo "✓ Test 2 PASSED" || echo "✗ Test 2 FAILED"
	@echo ""
	@echo "Test 3: Embed with TeamTNT key pattern"
	./polyglot_embed test_image.gif albanian_virus.sh test3.gif 410d200d
	./polyglot_extract test3.gif test3_out.bin 410d200d
	@diff -q albanian_virus.sh test3_out.bin && echo "✓ Test 3 PASSED" || echo "✗ Test 3 FAILED"
	@rm -f test*.gif test*_out.bin
	@echo ""
	@echo "All tests completed!"

# Install to system (optional)
install: all
	@echo "Installing to /usr/local/bin..."
	install -m 755 polyglot_embed /usr/local/bin/
	install -m 755 polyglot_extract /usr/local/bin/
	@echo "Installed successfully!"
	@echo ""
	@echo "Usage:"
	@echo "  polyglot_embed <image> <payload> <output> [key]"
	@echo "  polyglot_extract <image> <output> [key]"
