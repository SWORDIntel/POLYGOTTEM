CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
LDFLAGS = -lm
TARGET = neural_steg

all: $(TARGET)

$(TARGET): neural_steg.c
	$(CC) $(CFLAGS) -o $(TARGET) neural_steg.c $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o *.ppm

test: $(TARGET)
	@echo "[*] Creating test cover image..."
	@convert -size 512x512 xc:white -pointsize 72 -draw "text 100,250 'Neural Steg'" cover.ppm 2>/dev/null || echo "Install ImageMagick for auto-generation"
	@echo "[*] Creating test secret..."
	@echo "This is secret data for neural steganography testing" > secret.bin
	@echo "[*] Running neural embedding..."
	@./$(TARGET) --cover cover.ppm --secret secret.bin --output stego.ppm

.PHONY: all clean test
