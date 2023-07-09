#!/bin/bash
set -eu

# TODO: apply a given patch (here or elsewhere?)
# TODO: compile (with a given command)

# run tests (collect number of failures)
TOTAL_ERRORS=0

pushd src/test/bin &> /dev/null

TESTS=("./run_test_1" "./run_test_2" "./run_test_3" "./run_test_4")

for test_file in ${!TESTS[@]}; do
  test_file="${TESTS[$i]}"
  test_errors="$(${test_file} 2>1 | grep "Number of errors: " | tail -1 | cut -d":" -f2 | xargs)"
  TOTAL_ERRORS=$((TOTAL_ERRORS + test_errors))
done

# TODO: revert patch

echo "tests failed: ${TOTAL_ERRORS}"
