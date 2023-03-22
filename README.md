# CrashRepair

A program repair tool for security vulnerabilities in C programs.

## Installation

To build and run a Docker image that contains only the tool and regression tests:

    make -C docker crepair
    docker run --rm -it crepair:tool


To build and run a Docker image that contains both the tool and benchmark:

    make -C docker aio
    docker run --rm -it crepair:aio

# Example

To run the tool on an example from the benchmark:

    cd /data/vulnloc/jasper/CVE-2016-8691
    crashrepair repair --no-fuzz bug.json

