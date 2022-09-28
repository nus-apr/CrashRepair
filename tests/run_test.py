#!/usr/bin/env python3
import argparse
import mmap
import os
import shutil
import subprocess
import sys
import re
import json

dir_path = os.path.dirname(os.path.realpath(__file__))


def read_json(file_path):
    json_data = None
    if os.path.isfile(file_path):
        with open(file_path, 'r') as in_file:
            content = in_file.readline()
            json_data = json.loads(content)
    return json_data


def write_as_json(data, output_file_path):
    content = json.dumps(data)
    with open(output_file_path, 'w') as out_file:
        out_file.writelines(content)


def run_analyze(test_dir):
    os.chdir(test_dir)
    analyze_command = "git clean -f; crepair --conf=repair.conf > analyze.log 2>&1"
    process = subprocess.Popen(analyze_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    process.wait()
    ret_code = process.returncode
    result = "SUCCESS"
    with open('analyze.log', 'rb', 0) as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as s:
            if s.find(b'FATAL ERROR') != -1:
                result = "ERROR"
            if s.find(b'Stack dump') != -1:
                result = "ERROR"
            if s.find(b'Runtime Error') != -1:
                result = "ERROR"
    return result


def run_repair(test_dir):
    os.chdir(test_dir)
    repair_command = "git clean -f; crashrepair repair --no-fuzz bug.json > repair.log 2>&1"
    process = subprocess.Popen(repair_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    process.wait()
    ret_code = process.returncode
    patch_dir = test_dir + "/patches"
    patch_count = 0
    if os.path.isdir(patch_dir):
        patch_count = len(os.listdir(patch_dir))
    result = "SUCCCESS({})".format(patch_count)
    with open('repair.log', 'rb', 0) as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as s:
            if s.find(b'FATAL ERROR') != -1:
                result = "ERROR"
            if s.find(b'Stack dump') != -1:
                result = "ERROR"

    if ret_code != 0:
        result = "CRASH"
    return result


def getListOfFiles(dirName):
    # create a list of file and sub directories
    # names in the given directory
    listOfFile = os.listdir(dirName)
    allFiles = list()
    # Iterate over all the entries
    for entry in listOfFile:
        # Create full path
        fullPath = os.path.join(dirName, entry)
        # If entry is a directory then get the list of files in this directory
        if os.path.isdir(fullPath):
            allFiles = allFiles + getListOfFiles(fullPath)
        else:
            allFiles.append(fullPath)

    return sorted(allFiles)


def run(args):
    total_test = 0
    total_analyzed = 0
    total_repaired = 0

    file_list = getListOfFiles(dir_path)
    result_stat = []
    count = 0
    for file_path in file_list:
        if "repair.conf" in file_path:
            test_dir = "/".join(file_path.split("/")[:-1])
            print("Test:{0:100} ".format(test_dir), end="\t")
            total_test += 1
            analyze_result = run_analyze(test_dir)
            repair_result = run_repair(test_dir)
            if analyze_result == "SUCCESS":
                total_analyzed += 1
            repair_result = run_repair(test_dir)
            if "SUCCESS" in repair_result:
                total_repaired += 1
            print(" analysis={} \t repair={}".format(analyze_result, repair_result))

            generated_file_list = getListOfFiles(test_dir)
            fix_location_found = len(list(filter(re.compile(".*fix-locations.json").match, generated_file_list)))
            localization_found = len(list(filter(re.compile(".*localization.json").match, generated_file_list)))
            source_map_found = len(list(filter(re.compile(".*source-mapping.json").match, generated_file_list)))
            mutation_found = len(list(filter(re.compile(".*mutations.json").match, generated_file_list)))
            super_mutant_found = len(list(filter(re.compile(".*-mutated").match, generated_file_list)))
            patch_list = list(filter(re.compile(".*.patch").match, generated_file_list))
            repair_generated = len(patch_list)
            repair_patched = 0
            repair_compiled = 0
            repair_pass_oracle = 0
            if patch_list:
                for patch_file_path in patch_list:
                    with open(patch_file_path, "r") as p_file:
                        buggy_file_path = p_file.readline().split(" ")[-1].replace("\n", "").strip()
                        patch_command = "patch " + buggy_file_path + " " + patch_file_path
                        process = subprocess.Popen(patch_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                        process.wait()
                        repair_patched = (int(process.returncode) == 0)
                        if repair_patched:
                            compile_command = "LLVM_COMPILER=clang CC=wllvm CXX=wllvm++ bash build.sh"
                            process = subprocess.Popen(compile_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                            process.wait()
                            repair_compiled = (int(process.returncode) == 0)
                            if repair_compiled:
                                test_command = "bash test.sh"
                                process = subprocess.Popen(test_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
                                process.wait()
                                repair_pass_oracle = (int(process.returncode) == 0)
                            revert_command = "patch -R " + buggy_file_path + " " + patch_file_path
                            process = subprocess.Popen(revert_command, shell=True, stdout=subprocess.DEVNULL,
                                                       stderr=subprocess.STDOUT)
                            process.wait()

            result_stat.append((test_dir.replace(dir_path, "").split("/"), fix_location_found, localization_found, source_map_found, mutation_found,
                                super_mutant_found, repair_generated, repair_patched, repair_compiled, repair_pass_oracle))
            clean_command = "git clean -f; git checkout HEAD -- {}".format(test_dir)
            process = subprocess.Popen(clean_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            process.wait()

    
    print("Test completed\n")
    print("Total tests executed: {}".format(total_test))
    print("Total tests analyzed: {}({})".format(total_analyzed, total_test - total_analyzed))
    print("Total tests repaired: {}({})".format(total_repaired, total_test - total_repaired))
    write_as_json(result_stat, dir_path + "/summary.json")

    for file_path in file_list:
        if "bug.json" not in file_path:
            continue

        test_dir = os.path.dirname(file_path)
        from_analyze_log = os.path.join(test_dir, "analyze.log")
        from_repair_log = os.path.join(test_dir, "repair.log")

        rel_test_dir = os.path.relpath(test_dir, dir_path)
        log_dir = os.path.join("/logs", rel_test_dir)
        to_analyze_log = os.path.join(log_dir, "analyze.log")
        to_repair_log = os.path.join(log_dir, "repair.log")

        os.makedirs(log_dir, exist_ok=True)
        if os.path.isfile(from_analyze_log):
            shutil.copyfile(from_analyze_log, to_analyze_log)
        if os.path.isfile(from_repair_log):
            shutil.copyfile(from_repair_log, to_repair_log)


def main():
    parser = argparse.ArgumentParser("runs the HiFix test suite")
    parser.add_argument("--persist-logs", action="store_true", help="copies log files to the mounted logs directory")
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
