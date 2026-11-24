# Host build of the portable firmware core + vector test.
#   make -C firmware/common/test            (uses $(CC), default cc)
#   make -C firmware/common/test SAN=1      (ASan + UBSan, gcc/clang on Linux/macOS)
CC ?= cc
ROOT := ../../..
SRC := ../src/mf_crypto_ref.c ../src/mf_crypto_common.c ../src/mf_proto.c ../src/mf_mesh.c test_main.c
CFLAGS ?= -std=c99 -O2 -Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion -Wno-sign-conversion
ifeq ($(SAN),1)
CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer -g
endif

all: run

mf_host_test: $(SRC) $(wildcard ../include/*.h) json_mini.h
	$(CC) $(CFLAGS) -I../include -o $@ $(SRC)

run: mf_host_test
	./mf_host_test $(ROOT)/vectors/meshfind_vectors.json

clean:
	rm -f mf_host_test mf_host_test.exe

.PHONY: all run clean
