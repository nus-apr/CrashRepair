#!/bin/bash
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
benchmark_name=$(echo $script_dir | rev | cut -d "/" -f 3 | rev)
project_name=$(echo $script_dir | rev | cut -d "/" -f 2 | rev)
bug_id=$(echo $script_dir | rev | cut -d "/" -f 1 | rev)
dir_name=/data//$benchmark_name/$project_name/$bug_id

cd $dir_name/src

PROJECT_CFLAGS="-static -fsanitize=address -ggdb"
PROJECT_CPPFLAGS="-static -fsanitize=address  -ggdb"
PROJECT_LDFLAGS="-static  -fsanitize=address"

if [[ -n "${CFLAGS}" ]]; then
  PROJECT_CFLAGS="${PROJECT_CFLAGS} ${CFLAGS}"
fi
if [[ -n "${CPPFLAGS}" ]]; then
  PROJECT_CPPFLAGS="${PROJECT_CPPFLAGS} ${CPPFLAGS}"
fi
if [[ -n "${LDFLAGS}" ]]; then
  PROJECT_LDFLAGS="${PROJECT_LDFLAGS} ${LDFLAGS}"
fi

make CFLAGS="${PROJECT_CFLAGS}" CPPFLAGS="${PROJECT_CPPFLAGS}" LDFLAGS="${PROJECT_LDFLAGS}" -j`nproc`
