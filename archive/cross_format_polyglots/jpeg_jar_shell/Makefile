CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
TARGET = jpeg_jar_shell_gen

all: $(TARGET)

$(TARGET): jpeg_jar_shell_polyglot.c
	$(CC) $(CFLAGS) -o $(TARGET) jpeg_jar_shell_polyglot.c

clean:
	rm -f $(TARGET) *.o PolyglotDemo.java PolyglotDemo.class

.PHONY: all clean
