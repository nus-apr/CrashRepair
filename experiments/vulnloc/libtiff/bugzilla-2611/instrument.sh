#!/bin/bash
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
benchmark_name=$(echo $script_dir | rev | cut -d "/" -f 3 | rev)
project_name=$(echo $script_dir | rev | cut -d "/" -f 2 | rev)
bug_id=$(echo $script_dir | rev | cut -d "/" -f 1 | rev)
dir_name=/data//$benchmark_name/$project_name/$bug_id

cat <<EOF > $script_dir/repair.conf
dir_exp:$dir_name
tag_id:$bug_id
src_directory:$dir_name/src
binary_path:$dir_name/src/tools/tiffmedian
config_command:skip
build_command:make CC=crepair-cc CXX=crepair-cxx CFLAGS="-g -O0 -static" CXXFLAGS="-g -O0 -static" LDFLAGS="-static"
test_input_list:\$POC foo
poc_list:$script_dir/tests/1.tif
klee_flags:--link-llvm-lib=/CrashRepair/lib/libcrepair_proxy.bca
EOF

cd $dir_name/src
sed -i 's/fabs/fabs_trident/g' libtiff/tif_luv.c
git config --global user.email "you@example.com"
git config --global user.name "Your Name"
git add  libtiff/tif_luv.c
git commit -m 'replace fabs with proxy function'

CC=crepair-cc ./configure CFLAGS="-g -O0" --enable-static --disable-shared
make CC=crepair-cc CXX=crepair-cxx CFLAGS="-g -O0 -static" CXXFLAGS="-g -O0 -static" LDFLAGS="-static" -j`nproc`