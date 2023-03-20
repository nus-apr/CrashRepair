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

project_url=https://github.com/vadz/libtiff.git
fix_commit_id=43bc256d8ae44b92d2734a3c5bc73957a4d7c1ec
bug_commit_id=9a72a69

cd $dir_name
git clone $project_url src
cd src
git checkout $bug_commit_id
git format-patch -1 $fix_commit_id
cp *.patch $dir_name/dev-patch/fix.patch

./autogen.sh

cd $dir_name/src
sed -i 's/fabs/fabs_crepair/g' libtiff/tif_luv.c
git config --global user.email "you@example.com"
git config --global user.name "Your Name"
git add  libtiff/tif_luv.c
git commit -m 'replace fabs with proxy function'

# see #62
find tools -name "*.c" | xargs -n1 sed -i 's@"tif_config.h"@"../libtiff/tif_config.h"@g'
find tools -name "*.c" | xargs -n1 sed -i 's@"tiffio.h"@"../libtiff/tiffio.h"@g'
find tools -name "*.h" | xargs -n1 sed -i 's@"tif_config.h"@"../libtiff/tif_config.h"@g'
find tools -sed -i 's@"tiffio.h"@"./tiffio.h"@g' libtiff/tiffio.h
sed -i 's@"tiffvers.h"@"./tiffvers.h"@g' libtiff/tiffio.h
sed -i 's@"tiffio.h"@"./tiffio.h"@g' libtiff/tiffiop.h
git add libtiff/*.h tools/*.c tools/*.h
git commit -m "resolve ambiguity in includes"

CC=crepair-cc ./configure CFLAGS="-g -O0" --enable-static --disable-shared
make CC=crepair-cc CXX=crepair-cxx CFLAGS="-g -O0 -static" CXXFLAGS="-g -O0 -static" LDFLAGS="-static" -j`nproc`

cat <<EOF > $script_dir/repair.conf
dir_exp:$dir_name
tag_id:$bug_id
src_directory:$dir_name/src
binary_path:$dir_name/src/tools/tiffmedian
config_command:skip
build_command:make CC=crepair-cc CXX=crepair-cxx CFLAGS="-g -O0 -static" CXXFLAGS="-g -O0 -static" LDFLAGS="-static"
test_input_list:\$POC foo
poc_list:$script_dir/tests/1.tif
EOF

cat <<EOF > $dir_name/bug.json
{
  "project": {
    "name": "$project_name"
  },
  "name": "$bug_id",
  "binary": "$dir_name/src/tools/tiffmedian",
  "crash": {
    "command": "\$POC out.tiff",
    "input": "$script_dir/tests/1.tif",
    "extra-klee-flags": "",
    "expected-exit-code": 0
  },
  "source-directory": "src",
  "build": {
    "directory": "src",
    "binary": "$dir_name/src/tools/tiffmedian",
    "commands": {
      "prebuild": "./configure --enable-static --disable-shared",
      "clean": "make clean",
      "build": "make"
    },
    "sanitizerflags": "-fsanitize=integer-divide-by-zero"
  },
   "fuzzer": {
    "seed": 3,
    "crash-tag": "runtime;tif_ojpeg.c:816",
    "mutate-range": "default",
    "binary-path": "$dir_name/src/tools/tiffmedian",
    "timeout": {
      "local": 300,
      "global": 300
    },
    "proof-of-crash": {
      "format": ["bfile"],
      "values": ["$script_dir/tests/1.tif"],
      "commands": {
        "crash": ["$dir_name/src/tools/tiffmedian", "***", "out1.tiff"],
        "trace": ["$dir_name/src/tools/tiffmedian", "***", "out2.tiff"]
      }
    }
  }
}
EOF
