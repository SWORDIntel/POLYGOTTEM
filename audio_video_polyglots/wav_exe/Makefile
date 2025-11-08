CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
LDFLAGS = -lm
TARGET = wav_exe_gen

all: $(TARGET)

$(TARGET): wav_exe_polyglot.c
	$(CC) $(CFLAGS) -o $(TARGET) wav_exe_polyglot.c $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o *.wav

.PHONY: all clean
