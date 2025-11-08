CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
TARGET = pdf_exploit_gen

all: $(TARGET)

$(TARGET): pdf_exploit_polyglot.c
	$(CC) $(CFLAGS) -o $(TARGET) pdf_exploit_polyglot.c

clean:
	rm -f $(TARGET) *.o *.pdf

.PHONY: all clean
