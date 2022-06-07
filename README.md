# CrashRepair
C Repair tool for Program Crashes

## Build and Dependencies
We provide a ready-made container which includes all necessary environment set-up
to deploy and run our tool. Dependencies include:

* LLDB
* LLVM/Clang
* Klee
* LibASAN/LibUBSAN


Build and run a container:

    docker build -t rshariffdeen/crepair .
    docker run --rm -ti rshariffdeen/crepair /bin/bash


# Running Example
This repository includes several getting-started examples covering different types of program crashes

## Division by Zero
    crepair --conf=tests/bug-types/div-zero/div-zero-1/repair.conf

## Integer Overflow
    crepair --conf=tests/bug-types/int-overflow/int-overflow-1/repair.conf

## Null-Pointer Dereference
    crepair --conf=tests/bug-types/null-ptr/null-ptr-1/repair.conf
