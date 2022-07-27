#!/bin/bash
set -eu

HERE_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
REPO_ROOT=$(readlink -f "${HERE_DIR}/../../../../")
REPAIR_BIN="${REPO_ROOT}/source-repair/build/src/crashrepairfix/crashrepairfix"
LLVM11_INCLUDE_DIR="/opt/llvm11/lib/clang/11.1.0/include"

pushd "${HERE_DIR}" &> /dev/null

${REPAIR_BIN} \
  --localization-filename localization.json \
  -p src/compile_commands.json \
  src/test.c \
  -extra-arg=-I/opt/llvm11/lib/clang/11.1.0/include
