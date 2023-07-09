#!/bin/bash
set -eu

# TODO first compile the harness:
# cc -o runsuite `xml2-config --cflags` runsuite.c `xml2-config --libs` -lpthread

# TODO: apply a given patch (here or elsewhere?)
# TODO: compile (with a given command)

# run tests
TOTAL_ERRORS="$(./runsuite 2>1 | tail -1 | cut -d"," -f2 | cut -d" " -f2 | xargs)"

# TODO: revert patch

echo "tests failed: ${TOTAL_ERRORS}"
