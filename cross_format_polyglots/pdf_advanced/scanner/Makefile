CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
LDFLAGS = -lz
TARGET = pdf_fuzzer

all: $(TARGET)

$(TARGET): pdf_object_fuzzer.c
	$(CC) $(CFLAGS) -o $(TARGET) pdf_object_fuzzer.c $(LDFLAGS)

test: $(TARGET)
	@echo "[*] Generating fuzz corpus..."
	@./$(TARGET) --all --iterations 10 --output fuzz_corpus
	@echo "[*] Testing fuzzing output..."
	@for f in fuzz_corpus/*.pdf; do \
		echo "Testing: $$f"; \
		file "$$f" || true; \
	done

clean:
	rm -f $(TARGET) *.o
	rm -rf fuzzed/ fuzz_corpus/

.PHONY: all test clean
