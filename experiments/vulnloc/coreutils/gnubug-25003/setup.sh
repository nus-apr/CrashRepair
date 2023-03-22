#!/bin/bash
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
benchmark_name=$(echo $script_dir | rev | cut -d "/" -f 3 | rev)
project_name=$(echo $script_dir | rev | cut -d "/" -f 2 | rev)
bug_id=$(echo $script_dir | rev | cut -d "/" -f 1 | rev)
dir_name=/data/$benchmark_name/$project_name/$bug_id
current_dir=$PWD
mkdir -p $dir_name
cd $dir_name
mkdir dev-patch

project_url=https://github.com/coreutils/coreutils.git
fix_commit_id=4954f79
bug_commit_id=68c5eec

cd $dir_name
git clone $project_url src
cd src
git checkout $bug_commit_id
touch src/a

./bootstrap

cat <<EOF > $dir_name/bug.json
{
  "project": {
    "name": "$project_name"
  },
  "name": "$bug_id",
  "binary": "$dir_name/src/src/split",
  "crash": {
    "command": "-n7/75 /dev/null",
    "input": "",
    "extra-klee-flags": "",
    "expected-exit-code": 0
  },
  "source-directory": "src",
  "build": {
    "directory": "src",
    "binary": "$dir_name/src/src/split",
    "sanitizerflags": "-fsanitize=address",
    "commands": {
      "prebuild": "FORCE_UNSAFE_CONFIGURE=1 ./configure CFLAGS=\"-ggdb -fPIC -fPIE \${CFLAGS:-}\" CXXFLAGS=\"-ggdb -fPIC -fPIE \${CXXFLAGS:-}\"",
      "clean": "make clean",
      "build": "make CFLAGS=\"-ggdb -fPIC -fPIE \${CFLAGS:-}\" CXXFLAGS=\"-ggdb -fPIC -fPIE \${CXXFLAGS:-}\" LDFLAGS=\"\${LDFLAGS:-}\" src/make-prime-list"
    }
  },
   "fuzzer": {
    "seed": 3,
    "crash-tag": "asan;1;src/split.c:987",
    "store-all-inputs": true,
    "mutate-range": "1~1000;1~1000",
    "timeout": {
      "local": 300,
      "global": 300
    },
    "proof-of-crash": {
      "format": ["int", "int"],
      "values": ["7", "75"],
      "commands": {
        "crash": ["$dir_name/src/split", "-n***/***", "out2"],
        "trace": ["$dir_name/src/split", "-n***/***", "out1"]
      }
    }
  }
}
EOF
