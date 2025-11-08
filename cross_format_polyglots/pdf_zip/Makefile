CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
TARGET = pdf_zip_gen

all: $(TARGET)

$(TARGET): pdf_zip_polyglot.c
	$(CC) $(CFLAGS) -o $(TARGET) pdf_zip_polyglot.c

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
