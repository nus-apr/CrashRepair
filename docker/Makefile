all: install

builder:
	docker build -f Dockerfile.builder -t crepair:builder .

sourcerepair:
	docker build -t crepair:sourcerepair ../source-repair

z3: builder
	docker build -f Dockerfile.z3 -t crepair:z3 .

llvm-6: builder
	docker build -f Dockerfile.llvm-6 -t crepair:llvm-6 .

llvm-11: builder
	docker build -f Dockerfile.llvm-11 -t crepair:llvm-11 .

klee: builder llvm-6 z3
	docker build -f Dockerfile.klee -t crepair:klee .

fuzzer: builder
	docker build -f Dockerfile.fuzzer -t crepair:fuzzer ..

crepair: builder klee llvm-11 sourcerepair
	docker build -f Dockerfile.crepair -t crepair:tool ..

install: crepair

.PHONY: builder llvm-6 llvm-11 z3 klee crepair fuzzer install
