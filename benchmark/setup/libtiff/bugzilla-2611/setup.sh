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

./configure --enable-static --disable-shared
