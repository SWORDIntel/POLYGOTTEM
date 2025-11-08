CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
TARGET = png_audio_steg

all: $(TARGET)

$(TARGET): png_audio_steg.c
	$(CC) $(CFLAGS) -o $(TARGET) png_audio_steg.c

clean:
	rm -f $(TARGET) *.o *.png output.bin

.PHONY: all clean
