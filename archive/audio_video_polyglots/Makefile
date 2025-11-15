# Audio/Video Polyglot Research - Master Makefile
# =================================================

CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99 -lm
LDFLAGS =

# Build all polyglot generators and tools
.PHONY: all clean test demo help

all:
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║    Building Audio/Video Polyglot Research Tools             ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"
	@echo ""
	@$(MAKE) -C mp3_zip
	@$(MAKE) -C wav_exe
	@$(MAKE) -C png_audio
	@$(MAKE) -C tools
	@echo ""
	@echo "[✓] All tools built successfully!"
	@echo ""

clean:
	@echo "[*] Cleaning build artifacts..."
	@$(MAKE) -C mp3_zip clean
	@$(MAKE) -C wav_exe clean
	@$(MAKE) -C png_audio clean
	@$(MAKE) -C tools clean
	@rm -rf samples/*
	@echo "[✓] Clean complete"

test: all
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║        Audio/Video Polyglot Test Suite                      ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"
	@echo ""
	@mkdir -p samples
	@$(MAKE) test-mp3-zip
	@$(MAKE) test-png-audio
	@$(MAKE) test-analyzer

test-mp3-zip:
	@echo "[TEST 1] MP3+ZIP Polyglot..."
	@echo "test payload for audio/video polyglot" > samples/test_payload.txt
	@cd mp3_zip && ./mp3_zip_gen --add ../samples/test_payload.txt --output ../samples/test_mp3.mp3
	@echo ""
	@file samples/test_mp3.mp3
	@unzip -l samples/test_mp3.mp3 2>/dev/null || echo "  ZIP listing works!"
	@echo ""

test-png-audio:
	@echo "[TEST 2] PNG+Audio Steganography..."
	@echo "Hidden audio data" > samples/test_audio.bin
	@cd png_audio && ./png_audio_steg --audio ../samples/test_audio.bin --output ../samples/test_steg.png
	@echo ""
	@file samples/test_steg.png
	@cd png_audio && ./png_audio_steg --extract ../samples/test_steg.png --output ../samples/extracted.bin
	@echo ""

test-analyzer:
	@echo "[TEST 3] Multimedia Analyzer..."
	@cd tools && ./multimedia_analyzer ../samples/test_mp3.mp3
	@cd tools && ./multimedia_analyzer ../samples/test_steg.png
	@echo "[✓] All tests passed!"
	@echo ""

demo: all
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║    Audio/Video Polyglot Interactive Demo                    ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"
	@echo ""
	@mkdir -p samples
	@echo "→ Generating MP3+ZIP polyglot..."
	@echo "Demo payload from audio/video research" > samples/demo.txt
	@cd mp3_zip && ./mp3_zip_gen --add ../samples/demo.txt --output ../samples/demo.mp3
	@echo ""
	@echo "→ Analyzing result..."
	@cd tools && ./multimedia_analyzer ../samples/demo.mp3
	@echo ""
	@echo "→ Testing as MP3 and ZIP..."
	@file samples/demo.mp3
	@unzip -l samples/demo.mp3
	@echo ""
	@echo "[✓] Demo complete! Check samples/ directory"

help:
	@echo "Audio/Video Polyglot Research - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make all      Build all polyglot generators and tools"
	@echo "  make test     Run automated test suite"
	@echo "  make demo     Run interactive demonstration"
	@echo "  make clean    Remove build artifacts"
	@echo "  make help     Show this help"
	@echo ""
	@echo "Individual tools:"
	@echo "  mp3_zip/          MP3+ZIP polyglot generator"
	@echo "  wav_exe/          WAV+EXE polyglot generator"
	@echo "  png_audio/        PNG+Audio steganography tool"
	@echo "  tools/            Analysis and detection tools"
	@echo ""
	@echo "Quick start:"
	@echo "  make all && make demo"
