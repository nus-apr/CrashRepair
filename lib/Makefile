CC=gcc
CFLAGS=-I $(KLEE_INCLUDE_PATH)

DEP=crepair_runtime.h
SRC=crepair_runtime.c
PROXY_C=crepair_proxy.c
PROXY_OBJ=crepair_proxy.o
OBJ_KLEE=$(SRC:%.c=%.o)

all: crepair_runtime.o libcrepair_runtime.a libcrepair_runtime.so libcrepair_runtime.bca libcrepair_proxy.so libcrepair_proxy.a libcrepair_proxy.bca

%.o: %.c $(DEP)
	wllvm -g -fPIC -O0 -c -o $@ $< $(CFLAGS)

libcrepair_proxy.so: $(PROXY_OBJ)
	wllvm -fPIC -shared -o $@ $(PROXY_OBJ)

libcrepair_proxy.a: $(PROXY_OBJ)
	llvm-ar rcs $@ $(PROXY_OBJ)

libcrepair_runtime.so: $(OBJ_KLEE)
	wllvm -fPIC -shared -o $@ $(OBJ_KLEE)

libcrepair_runtime.a: $(OBJ_KLEE)
	llvm-ar rcs $@ $(OBJ_KLEE)

libcrepair_runtime.bca: libcrepair_runtime.a
	extract-bc libcrepair_runtime.a

libcrepair_proxy.bca: libcrepair_proxy.a
	extract-bc libcrepair_proxy.a

clean:
	rm -f *.o
	rm -f *.a
	rm -f *.bca
	rm -f *.so
