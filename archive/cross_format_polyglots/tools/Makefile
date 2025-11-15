CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
TARGET = polyglot_analyzer

all: $(TARGET)

$(TARGET): polyglot_analyzer.c
	$(CC) $(CFLAGS) -o $(TARGET) polyglot_analyzer.c

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
