#!/bin/bash
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
benchmark_name=$(echo $script_dir | rev | cut -d "/" -f 3 | rev)
project_name=$(echo $script_dir | rev | cut -d "/" -f 2 | rev)
bug_id=$(echo $script_dir | rev | cut -d "/" -f 1 | rev)
dir_name=/data//$benchmark_name/$project_name/$bug_id
current_dir=$PWD
mkdir -p $dir_name
cd $dir_name
mkdir dev-patch

project_url=https://github.com/coreutils/coreutils.git
fix_commit_id=1d0f1b7ce10807290715d0b7c4637ac9d4fc7821
bug_commit_id=658529a10e05d06524d5f591a08f04c04159b4cc

cd $dir_name
git clone $project_url src
cd src
git checkout $bug_commit_id
git format-patch -1 $fix_commit_id
cp *.patch $dir_name/dev-patch/fix.patch

./bootstrap
FORCE_UNSAFE_CONFIGURE=1 CC=crepair-cc ./configure CFLAGS="-g -O0 -static -fPIE -Wno-error" CXXFLAGS="-g -O0 -static -fPIE -Wno-error"
make CC=crepair-cc CXX=crepair-cxx CFLAGS="-ggdb -fPIC -fPIE -g -O0 -Wno-error" CXXFLAGS="-ggdb -fPIC -fPIE -g -O0 -Wno-error" LDFLAGS="-static"

cat <<EOF > $script_dir/repair.conf
dir_exp:$dir_name
tag_id:$bug_id
src_directory:$dir_name/src
binary_path:$dir_name/src/src/make-prime-list
config_command:skip
build_command:make CC=crepair-cc CXX=crepair-cxx CFLAGS="-ggdb -fPIC -fPIE -g -O0 -Wno-error" CXXFLAGS="-ggdb -fPIC -fPIE -g -O0 -Wno-error" LDFLAGS="-static" src/make-prime-list
test_input_list:15
klee_flags:--link-llvm-lib=/CrashRepair/lib/libcrepair_proxy.bca
EOF


cat <<EOF > $dir_name/bug.json
{
  "project": {
    "name": "$project_name"
  },
  "name": "$bug_id",
  "binary": "$dir_name/src/src/make-prime-list",
  "crash": {
    "command": "15",
    "input": "",
    "extra-klee-flags": "",
    "expected-exit-code": 0
  },
  "source-directory": "src",
  "build": {
    "directory": "src",
    "binary": "$dir_name/src/src/make-prime-list",
    "sanitizerflags": "-fsanitize=address",
    "commands": {
      "prebuild": "FORCE_UNSAFE_CONFIGURE=1 ./configure CFLAGS=\"-ggdb -fPIC -fPIE \${CFLAGS:-}\" CXXFLAGS=\"-ggdb -fPIC -fPIE \${CXXFLAGS:-}\"",
      "clean": "make clean",
      "build": "make CFLAGS=\"-ggdb -fPIC -fPIE \${CFLAGS:-}\" CXXFLAGS=\"-ggdb -fPIC -fPIE \${CXXFLAGS:-}\" LDFLAGS=\"\${LDFLAGS:-}\" src/make-prime-list"
    }
  },
   "fuzzer": {
    "seed": 3,
    "crash-tag": "asan;0;src/make-prime-list.c:214",
    "binary-path": "$dir_name/src/make-prime-list",
    "mutate-range": "-1000~1000",
    "timeout": {
      "local": 300,
      "global": 300
    },
    "proof-of-crash": {
      "format": ["int"],
      "values": ["5"],
      "commands": {
        "crash": ["$dir_name/src/make-prime-list", "***"],
        "trace": ["$dir_name/src/make-prime-list", "***"]
      }
    }
  }
}
EOF
