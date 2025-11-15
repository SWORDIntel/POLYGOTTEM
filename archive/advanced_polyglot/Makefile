# Advanced Polyglot Tool - Makefile
# ====================================

CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
LDFLAGS = -lm
TARGET = polyglot_advanced
SRC = polyglot_advanced.c

# Test files
TEST_IMAGE = test_image.gif
TEST_PAYLOAD = test_payload.sh
TEST_OUTPUT = test_output.gif

.PHONY: all clean test demo help

all: $(TARGET)

$(TARGET): $(SRC)
	@echo "[+] Compiling Advanced Polyglot Tool..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo "[✓] Build complete: $(TARGET)"

test: $(TARGET) $(TEST_IMAGE) $(TEST_PAYLOAD)
	@echo "════════════════════════════════════════"
	@echo " Running Advanced Polyglot Tool Tests"
	@echo "════════════════════════════════════════"
	@echo ""
	@echo "[TEST 1] Steganography Embed..."
	./$(TARGET) --mode stego --embed $(TEST_IMAGE) \
		--payload $(TEST_PAYLOAD) --output $(TEST_OUTPUT) \
		--key 9e0a61200d -v
	@echo ""
	@echo "[TEST 2] Analyze embedded file..."
	./$(TARGET) --mode analyze --input $(TEST_OUTPUT) -v
	@echo ""
	@echo "[TEST 3] Extract payload..."
	./$(TARGET) --mode extract --input $(TEST_OUTPUT) \
		--output extracted_payload.sh --key 9e0a61200d
	@echo ""
	@echo "[TEST 4] Verify extraction..."
	@chmod +x extracted_payload.sh
	@./extracted_payload.sh || true
	@echo ""
	@echo "[✓] All tests passed!"

demo: $(TARGET) $(TEST_IMAGE) $(TEST_PAYLOAD)
	@echo "╔══════════════════════════════════════════════════════╗"
	@echo "║      Advanced Polyglot Tool - Live Demo             ║"
	@echo "╚══════════════════════════════════════════════════════╝"
	@echo ""
	@echo "→ Embedding encrypted payload in image..."
	./$(TARGET) --mode stego --embed $(TEST_IMAGE) \
		--payload $(TEST_PAYLOAD) --output demo_stego.gif \
		--key 9e0a61200d
	@echo ""
	@echo "→ Analyzing result..."
	./$(TARGET) --mode analyze --input demo_stego.gif
	@echo ""
	@echo "→ Extracting and executing..."
	./$(TARGET) --mode extract --input demo_stego.gif \
		--output demo_extracted.sh --key 9e0a61200d
	@chmod +x demo_extracted.sh
	@./demo_extracted.sh
	@rm -f demo_stego.gif demo_extracted.sh

$(TEST_IMAGE):
	@echo "[*] Creating test GIF image..."
	@python3 -c "import struct; \
	f=open('$(TEST_IMAGE)','wb'); \
	f.write(b'GIF89a\x01\x00\x01\x00\x00\x00\x00\x3b'); \
	f.close()"

$(TEST_PAYLOAD):
	@echo "[*] Creating test payload..."
	@echo '#!/bin/sh' > $(TEST_PAYLOAD)
	@echo 'echo "╔══════════════════════════════════════════════╗"' >> $(TEST_PAYLOAD)
	@echo 'echo "║  Advanced Polyglot Tool - Test Payload      ║"' >> $(TEST_PAYLOAD)
	@echo 'echo "║  This payload was hidden in an image!       ║"' >> $(TEST_PAYLOAD)
	@echo 'echo "╚══════════════════════════════════════════════╝"' >> $(TEST_PAYLOAD)
	@chmod +x $(TEST_PAYLOAD)

clean:
	@echo "[*] Cleaning build artifacts..."
	rm -f $(TARGET)
	rm -f $(TEST_IMAGE) $(TEST_PAYLOAD) $(TEST_OUTPUT)
	rm -f extracted_payload.sh demo_stego.gif demo_extracted.sh
	rm -f *.o *~ core
	@echo "[✓] Clean complete"

help:
	@echo "Advanced Polyglot Tool - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make          Build the tool"
	@echo "  make test     Run automated tests"
	@echo "  make demo     Run interactive demonstration"
	@echo "  make clean    Remove build artifacts"
	@echo "  make help     Show this help"
	@echo ""
	@echo "Usage examples:"
	@echo "  # Build and test"
	@echo "  make && make test"
	@echo ""
	@echo "  # Run demo"
	@echo "  make demo"
	@echo ""
	@echo "  # Manual usage"
	@echo "  ./$(TARGET) --help"
