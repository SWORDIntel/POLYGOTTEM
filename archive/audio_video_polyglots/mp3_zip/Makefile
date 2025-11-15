CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
TARGET = mp3_zip_gen

all: $(TARGET)

$(TARGET): mp3_zip_polyglot.c
	$(CC) $(CFLAGS) -o $(TARGET) mp3_zip_polyglot.c

clean:
	rm -f $(TARGET) *.o *.mp3

.PHONY: all clean
