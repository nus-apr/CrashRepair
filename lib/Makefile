CC=gcc
CFLAGS=-I $(KLEE_INCLUDE_PATH)

DEP=crepair_runtime.h
SRC=crepair_runtime.c
PROXY_C=crepair_proxy.c
PROXY_OBJ=crepair_proxy.o
GHOST_C=crepair_ghost.c
GHOST_OBJ=crepair_ghost.o
RUNTIME_C=crepair_runtime.c
RUNTIME_OBJ=crepair_runtime.o


all: libcrepair_ghost.so libcrepair_ghost.a crepair_runtime.o libcrepair_runtime.a libcrepair_runtime.so libcrepair_runtime.bca libcrepair_proxy.so libcrepair_proxy.a libcrepair_proxy.bca

%.o: %.c $(DEP)
	wllvm -g -fPIC -O0 -c -o $@ $< $(CFLAGS)

libcrepair_proxy.so: $(PROXY_OBJ)
	wllvm -fPIC -shared -o $@ $(PROXY_OBJ)

libcrepair_proxy.a: $(PROXY_OBJ)
	llvm-ar rcs $@ $(PROXY_OBJ)

libcrepair_ghost.so: $(GHOST_OBJ)
	wllvm -fPIC -shared -o $@ $(GHOST_OBJ)

libcrepair_ghost.a: $(GHOST_OBJ)
	llvm-ar rcs $@ $(GHOST_OBJ)

libcrepair_runtime.so: $(RUNTIME_OBJ)
	wllvm -fPIC -shared -o $@ $(RUNTIME_OBJ)

libcrepair_runtime.a: $(RUNTIME_OBJ)
	llvm-ar rcs $@ $(RUNTIME_OBJ)

libcrepair_runtime.bca: libcrepair_runtime.a
	extract-bc libcrepair_runtime.a

libcrepair_proxy.bca: libcrepair_proxy.a
	extract-bc libcrepair_proxy.a

clean:
	rm -f *.o
	rm -f *.a
	rm -f *.bca
	rm -f *.so
