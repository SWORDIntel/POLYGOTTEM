CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
TARGET = gif_html_gen

all: $(TARGET)

$(TARGET): gif_html_polyglot.c
	$(CC) $(CFLAGS) -o $(TARGET) gif_html_polyglot.c

clean:
	rm -f $(TARGET) *.o demo_payload.html

.PHONY: all clean
