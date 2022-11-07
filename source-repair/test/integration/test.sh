#!/bin/bash
set -eu

HERE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd "${HERE_DIR}" &> /dev/null
CRASHREPAIRFIX="${HERE_DIR}/../../build/src/crashrepairfix/crashrepairfix"

${CRASHREPAIRFIX} test.cpp --localization-filename localization.json
