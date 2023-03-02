# CrashRepair

A program repair tool for security vulnerabilities in C programs.

## Installation

To build and run a Docker image that contains only the tool and regression tests:

    make -C docker crepair
    docker run --rm -it crepair:tool


To build and run a Docker image that contains both the tool and benchmark:

    make -C docker aio
    docker run --rm -it crepair:aio

# Running Example
This repository includes several getting-started examples covering different types of program crashes

## Division by Zero
    crepair --conf=tests/bug-types/div-zero/div-zero-1/repair.conf

## Integer Overflow
    crepair --conf=tests/bug-types/int-overflow/int-overflow-1/repair.conf

## Null-Pointer Dereference
    crepair --conf=tests/bug-types/null-ptr/null-ptr-1/repair.conf
