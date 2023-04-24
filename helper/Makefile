CC = gcc
CFLAGS = -I../include
CFLAGS += -static
CFLAGS += -w


all: clean helper

.PHONY: helper
helper:
	$(CC) $(CFLAGS) speHelper.c -o speHelper

shellcode.h: shellcode
	xxd -i $^ $@

shellcode: shellcode.asm
	nasm -f bin -o $@ $^

clean:
	rm -f speHelper shellcode.h shellcode
