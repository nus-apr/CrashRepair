all: install

deps:
	git submodule update --init --recursive

builder: deps
	docker build -f Dockerfile.builder -t crepair:builder .

sourcerepair:
	docker build -t crepair:sourcerepair ../source-repair

z3: builder
	docker build -f Dockerfile.z3 -t crepair:z3 .

# note that the image below isn't hosted on DockerHub:
# 	docker pull rshariffdeen/crepair:z3
# 	docker tag rshariffdeen/crepair:z3 crepair:z3

llvm-6: builder
	# docker build -f Dockerfile.llvm-6 -t crepair:llvm-6 .
    docker pull rshariffdeen/crepair:llvm-6
	docker tag rshariffdeen/crepair:llvm-6 crepair:llvm-6

# be aware that the following command can nondeterministically fail:
# docker pull christimperley/llvm11
llvm-11: builder
	docker pull christimperley/llvm11
	docker tag christimperley/llvm11 crepair:llvm-11

klee: builder llvm-6 z3
	docker build -f Dockerfile.klee -t crepair:klee .

# note that the images below aren't hosted on DockerHub:
# 	docker pull rshariffdeen/crepair:klee
# 	docker tag rshariffdeen/crepair:klee crepair:klee

fuzzer: builder
	docker build -f Dockerfile.fuzzer -t crepair:fuzzer ..

crepair: builder klee llvm-11 orchestrator sourcerepair
	docker build -f Dockerfile.crepair -t crepair:tool ..

orchestrator:
	docker build -t crepair:orchestrator ../orchestrator

install: experiments

experiments: crepair
	docker build -t crepair:experiments -f Dockerfile.vulnloc .

.PHONY: builder llvm-6 llvm-11 orchestrator z3 klee crepair fuzzer install experiments
