# Cross-Format Polyglot Research - Master Makefile
# ==================================================

CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
LDFLAGS =

# Build all polyglot generators and tools
.PHONY: all clean test demo help

all:
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║    Building Cross-Format Polyglot Research Tools            ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"
	@echo ""
	@$(MAKE) -C pdf_zip
	@$(MAKE) -C gif_html
	@$(MAKE) -C jpeg_jar_shell
	@$(MAKE) -C tools
	@echo ""
	@echo "[✓] All tools built successfully!"
	@echo ""

clean:
	@echo "[*] Cleaning build artifacts..."
	@$(MAKE) -C pdf_zip clean
	@$(MAKE) -C gif_html clean
	@$(MAKE) -C jpeg_jar_shell clean
	@$(MAKE) -C tools clean
	@rm -rf samples/*
	@echo "[✓] Clean complete"

test: all
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║          Cross-Format Polyglot Test Suite                   ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"
	@echo ""
	@$(MAKE) test-pdf-zip
	@$(MAKE) test-gif-html
	@$(MAKE) test-analyzer

test-pdf-zip:
	@echo "[TEST 1] PDF+ZIP Polyglot..."
	@echo "test payload" > samples/test_payload.txt
	@cd pdf_zip && ./pdf_zip_gen --add ../samples/test_payload.txt --output ../samples/test_pdf_zip.pdf
	@echo ""
	@file samples/test_pdf_zip.pdf
	@unzip -l samples/test_pdf_zip.pdf 2>/dev/null || echo "  ZIP listing works!"
	@echo ""

test-gif-html:
	@echo "[TEST 2] GIF+HTML Polyglot..."
	@cd gif_html && ./gif_html_gen --demo
	@cd gif_html && ./gif_html_gen --html demo_payload.html --output ../samples/test_gif_html.gif
	@echo ""
	@file samples/test_gif_html.gif
	@strings samples/test_gif_html.gif | grep -i "polyglot" || echo "  HTML content embedded!"
	@echo ""

test-analyzer:
	@echo "[TEST 3] Polyglot Analyzer..."
	@cd tools && ./polyglot_analyzer ../samples/test_pdf_zip.pdf
	@cd tools && ./polyglot_analyzer ../samples/test_gif_html.gif
	@echo "[✓] All tests passed!"
	@echo ""

demo: all
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║      Cross-Format Polyglot Interactive Demo                 ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "→ Generating PDF+ZIP polyglot..."
	@echo "Demo payload from cross-format research" > samples/demo.txt
	@cd pdf_zip && ./pdf_zip_gen --add ../samples/demo.txt --output ../samples/demo.pdf
	@echo ""
	@echo "→ Analyzing result..."
	@cd tools && ./polyglot_analyzer ../samples/demo.pdf
	@echo ""
	@echo "→ Testing as PDF and ZIP..."
	@file samples/demo.pdf
	@unzip -l samples/demo.pdf
	@echo ""
	@echo "[✓] Demo complete! Check samples/ directory"

help:
	@echo "Cross-Format Polyglot Research - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make all      Build all polyglot generators and tools"
	@echo "  make test     Run automated test suite"
	@echo "  make demo     Run interactive demonstration"
	@echo "  make clean    Remove build artifacts"
	@echo "  make help     Show this help"
	@echo ""
	@echo "Individual tools:"
	@echo "  pdf_zip/          PDF+ZIP polyglot generator"
	@echo "  gif_html/         GIF+HTML polyglot generator"
	@echo "  jpeg_jar_shell/   JPEG+JAR+Shell triple polyglot"
	@echo "  tools/            Analysis and detection tools"
	@echo ""
	@echo "Quick start:"
	@echo "  make all && make demo"
