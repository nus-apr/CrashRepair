#!/bin/bash
#
# This script runs CrashRepair on a single bug scenario from the dataset, specified by the name of
# the program the scenario belongs to (e.g., libtiff) and the scenario (e.g., bugzilla-2611), each
# given as separate arguments.
#
set -eu

umask 000

PROGRAM=$1
SCENARIO=$2

REPAIR_TIME_LIMIT="${REPAIR_TIME_LIMIT:-45}"
TEST_TIME_LIMIT="${TEST_TIME_LIMIT:-30}"
PATCH_LIMIT="${PATCH_LIMIT:-10}"

WORKDIR="/data/vulnloc/${PROGRAM}/${SCENARIO}"
RESULTS_DIR="/results/${PROGRAM}/${SCENARIO}"
LOG_DIR="/logs/${PROGRAM}/${SCENARIO}"
LOG_FILENAME="${LOG_DIR}/orchestrator.log"

pushd "${WORKDIR}"
mkdir -p "${LOG_DIR}"
mkdir -p "${RESULTS_DIR}"
stty cols 100
stty rows 100
crashrepair repair \
  --time-limit-minutes-validation "${REPAIR_TIME_LIMIT}" \
  --time-limit-seconds-test "${TEST_TIME_LIMIT}" \
  --patch-limit "${PATCH_LIMIT}" \
  bug.json \
  2>1 |& tee "${LOG_FILENAME}"

if [[ -d patches ]]; then
  cp -r patches "${RESULTS_DIR}"
fi
cp -r analysis "${RESULTS_DIR}"
cp report.json "${RESULTS_DIR}"

# fix permissions
chown -R ${HOST_UID}:${HOST_UID} "${LOG_DIR}"
chown -R ${HOST_UID}:${HOST_UID} "${RESULTS_DIR}"
