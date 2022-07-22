#!/bin/bash
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
benchmark_name=$(echo $script_dir | rev | cut -d "/" -f 3 | rev)
project_name=$(echo $script_dir | rev | cut -d "/" -f 2 | rev)
bug_id=$(echo $script_dir | rev | cut -d "/" -f 1 | rev)
dir_name=/data//$benchmark_name/$project_name/$bug_id

TEST_ID=$1
BINARY_PATH="$dir_name/src/tools/tiffmedian"





case "$1" in
    1)
        POC=$script_dir/tests/1.tif
        timeout 10 $BINARY_PATH $POC foo > $BINARY_PATH.log 2>&1
esac

