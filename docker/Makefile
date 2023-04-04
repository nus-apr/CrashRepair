all: install

deps:
	git submodule update --init --recursive

builder: deps
	docker build -f Dockerfile.builder -t crepair:builder .

sourcerepair:
	docker build -t crepair:sourcerepair ../source-repair

z3: builder
	docker build -f Dockerfile.z3 -t crepair:z3 .

llvm-6: builder
    docker pull christimperley/llvm-6
	docker tag christimperley/llvm-6 crepair:llvm-6

llvm-11: builder
	docker pull christimperley/llvm11
	docker tag christimperley/llvm11 crepair:llvm-11

klee: builder llvm-6 z3
	docker build -f Dockerfile.klee -t crepair:klee .

fuzzer: builder
	docker build -f Dockerfile.fuzzer -t crepair:fuzzer ..

crepair: builder klee llvm-11 orchestrator sourcerepair fuzzer
	docker build -t crepair:tool -f Dockerfile.crepair --target tool ..

orchestrator:
	docker build -t crepair:orchestrator ../orchestrator

install: aio

benchmark: builder klee llvm-11 orchestrator sourcerepair
	docker build -t crepair:benchmark -f Dockerfile.crepair --target benchmark ..

aio: crepair benchmark fuzzer
	docker build -t crepair:aio -f Dockerfile.crepair --target aio ..

.PHONY: benchmark builder llvm-6 llvm-11 orchestrator z3 klee crepair fuzzer install aio
