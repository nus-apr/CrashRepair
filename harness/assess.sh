#!/bin/bash
# assesses all patches for a given scenario

# find program and scenario name from the provided path
FULL_SCENARIO_PATH="$(realpath "$1")"
BUG_JSON="${FULL_SCENARIO_PATH}/bug.json"
SCENARIO="$(basename "${FULL_SCENARIO_PATH}")"
PROGRAM="$(basename "$(dirname ${FULL_SCENARIO_PATH}})")"

HELDOUT_DIRECTORY="/heldout/${PROGRAM}/${SCENARIO}"
PATCH_DIRECTORY="/results/${PROGRAM}/${SCENARIO}/patches"
SUMMARY_CSV="${HELDOUT_DIRECTORY}/${PROGRAM}-${SCENARIO}.heldout.csv"

function test_libxml2 {
  pushd "${FULL_SCENARIO_PATH}/src" &> /dev/null
  cc -o runsuite `xml2-config --cflags` runsuite.c `xml2-config --libs` -lpthread
  echo "$(./runsuite 2>1 | tail -1 | cut -d"," -f2 | cut -d" " -f2 | xargs)"
}

function evaluate_patch {
  pushd / &> /dev/null
  PATCH="$(realpath "$1")"
  PATCH_NAME="$(basename "$1")"
  HELDOUT_FILENAME="${HELDOUT_DIRECTORY}/${PATCH_NAME}.errors"
  echo "evaluating patch: ${PATCH_NAME}"

  # ensure that output directory exists
  mkdir -p "${HELDOUT_DIRECTORY}"

  # if we already have results for this patch, skip
  if [ -f "${HELDOUT_FILENAME}" ]; then
    echo "skipping patch: ${PATCH_NAME}"
    return
  fi

  # apply the patch
  echo "applying patch..."
  if ! patch -p0 < "${PATCH}"; then
    echo "FAILED TO APPLY PATCH: ${PATCH_NAME}"
    return
  fi
  echo "applied patch"

  # recompile the program
  echo "compiling program..."
  crashrepair rebuild "${BUG_JSON}" &> /dev/null
  echo "compiled program"

  # run the appropriate test harness
  # FIXME
  test_libxml2 "${PATCH}" > "${HELDOUT_FILENAME}"

  # revert the patch
  echo "reverting patch..."
  pushd / &> /dev/null
  patch -R -p0 < "${PATCH}"
  echo "reverted patch"
}

# iterate over each of the patches for the given program
find "${PATCH_DIRECTORY}" -name "*.diff" | sort | while read line; do
  evaluate_patch "${line}"
done

# collate results into a single CSV file
rm -f "${SUMMARY_CSV}"
touch "${SUMMARY_CSV}"
find "${HELDOUT_DIRECTORY}" -name "*.diff.errors" | sort | while read line; do
  HELDOUT_FILE="$(realpath "${line}")"
  SCORE=$(cat "${HELDOUT_FILE}" | xargs)
  echo "${HELDOUT_FILE}, ${SCORE}" >> "${SUMMARY_CSV}"
done
