CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
TARGET = multimedia_analyzer

all: $(TARGET)

$(TARGET): multimedia_analyzer.c
	$(CC) $(CFLAGS) -o $(TARGET) multimedia_analyzer.c

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
