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
fix_commit_id=d91aee
bug_commit_id=ca99c52

cd $dir_name
git clone $project_url src
cd src
git checkout $bug_commit_id
git format-patch -1 $fix_commit_id
cp *.patch $dir_name/dev-patch/fix.patch

./bootstrap
FORCE_UNSAFE_CONFIGURE=1 CC=crepair-cc ./configure CFLAGS="-g -O0 -static -fPIE -Wno-error" CXXFLAGS="-g -O0 -static -fPIE -Wno-error"
make CC=crepair-cc CXX=crepair-cxx CFLAGS="-ggdb -fPIC -fPIE -g -O0 -Wno-error" CXXFLAGS="-ggdb -fPIC -fPIE -g -O0 -Wno-error" LDFLAGS="-static"
echo "a" > $dir_name/src/src/a

cat <<EOF > $script_dir/repair.conf
dir_exp:$dir_name
tag_id:$bug_id
src_directory:$dir_name/src
binary_path:$dir_name/src/src/pr
config_command:skip
build_command:make CC=crepair-cc CXX=crepair-cxx CFLAGS="-ggdb -fPIC -fPIE -g -O0 -Wno-error" CXXFLAGS="-ggdb -fPIC -fPIE -g -O0 -Wno-error" LDFLAGS="-static" src/pr
test_input_list:"-S\$(printf "\t\t\t")" a -m \$POC
poc_list:$script_dir/tests/1.txt
klee_flags:--link-llvm-lib=/CrashRepair/lib/libcrepair_proxy.bca
mask_arg:0,1,2
EOF


cat <<EOF > $dir_name/bug.json
{
  "project": {
    "name": "$project_name"
  },
  "name": "$bug_id",
  "binary": "$dir_name/src/src/pr",
  "crash": {
    "command": "\"-S\$(printf \"\\t\\t\\t\")\" a -m \$POC",
    "input": "$script_dir/tests/1.txt",
    "extra-klee-flags": "",
    "expected-exit-code": 1
  },
  "source-directory": "src",
  "build": {
    "directory": "src",
    "binary": "$dir_name/src/src/pr",
    "sanitizerflags": "-fsanitize=address",
    "commands": {
      "prebuild": "FORCE_UNSAFE_CONFIGURE=1 ./configure CFLAGS=\"-ggdb -fPIC -fPIE \${CFLAGS:-}\" CXXFLAGS=\"-ggdb -fPIC -fPIE \${CXXFLAGS:-}\"",
      "clean": "make clean",
      "build": "make CFLAGS=\"-ggdb -fPIC -fPIE \${CFLAGS:-}\" CXXFLAGS=\"-ggdb -fPIC -fPIE \${CXXFLAGS:-}\" LDFLAGS=\"\${LDFLAGS:-}\" src/make-prime-list"
    }
  },
   "fuzzer": {
    "seed": 3,
    "crash-tag": "asan;0;src/pr.c:2241",
    "mutate-range": "default;default;default;default;default;default",
    "timeout": {
      "local": 300,
      "global": 300
    },
    "proof-of-crash": {
      "format": ["str", "str", "str", "str", "str", "str"],
      "values": ["\\\\", "t", "\\\\", "t", "\\\\", "t"],
      "commands": {
        "crash": ["$dir_name/src/pr", "-S$(printf "***")", "tmp2", "-m", "tmp2"],
        "trace": ["$dir_name/src/pr", "-S$(printf "***")", "tmp2", "-m", "tmp2"]
      }
    }
  }
}
EOF
