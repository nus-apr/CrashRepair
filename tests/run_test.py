#!/usr/bin/env python3.8
import argparse
import json
import mmap
import os
import re
import shutil
import subprocess
import typing as t

from dataclasses import dataclass

dir_path = os.path.dirname(os.path.realpath(__file__))
summary_path = os.path.join(dir_path, "summary.json")


@dataclass
class ScenarioSummary:
    repair_outcome: str
    analysis_outcome: str
    # TODO this should be collapsed into a set of dataclass fields
    result_stat: t.Tuple[t.Any]


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


def run_analyze(test_dir: str) -> str:
    analyze_command = "git clean -f; crepair --conf=repair.conf > analyze.log 2>&1"
    process = subprocess.Popen(analyze_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, cwd=test_dir)
    process.wait()
    ret_code = process.returncode
    result = "SUCCESS"
    analysis_log_filename = os.path.join(test_dir, "analyze.log")
    with open(analysis_log_filename, 'rb', 0) as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as s:
            if s.find(b'FATAL ERROR') != -1:
                result = "ERROR"
            if s.find(b'Stack dump') != -1:
                result = "ERROR"
            if s.find(b'Runtime Error') != -1:
                result = "ERROR"
    return result


def run_repair(test_dir: str) -> str:
    repair_command = "git clean -f; rm -rf analysis; crashrepair repair --no-fuzz bug.json > repair.log 2>&1"
    process = subprocess.Popen(repair_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, cwd=test_dir)
    process.wait()
    ret_code = process.returncode
    patch_dir = test_dir + "/patches"
    patch_count = 0
    if os.path.isdir(patch_dir):
        patch_count = len(os.listdir(patch_dir))
    result = "SUCCESS({})".format(patch_count)
    repair_log_filename = os.path.join(test_dir, "repair.log")
    with open(repair_log_filename, 'rb', 0) as f:
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


def run_test(test_dir: str) -> ScenarioSummary:
    analyze_result = run_analyze(test_dir)
    repair_result = run_repair(test_dir)

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

    # validate each candidate patch
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

    result_stat = (
        test_dir.replace(dir_path, "").split("/"),
        fix_location_found,
        localization_found,
        source_map_found,
        mutation_found,
        super_mutant_found,
        repair_generated,
        repair_patched,
        repair_compiled,
        repair_pass_oracle,
    )
    clean_command = "git clean -f; git checkout HEAD -- {}".format(test_dir)
    process = subprocess.Popen(clean_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, cwd=test_dir)
    process.wait()

    return ScenarioSummary(
        repair_outcome=repair_result,
        analysis_outcome=analyze_result,
        result_stat=result_stat,
    )


def run(args: argparse.Namespace) -> None:
    total_test = 0
    total_analyzed = 0
    total_repaired = 0

    file_list = getListOfFiles(dir_path)
    result_stat: t.List[t.Tuple[t.Any]] = []
    for file_path in file_list:
        # FIXME why not look for bug.json?
        if "repair.conf" not in file_path:
            continue

        # FIXME use os.path.dirname
        test_dir = "/".join(file_path.split("/")[:-1])
        total_test += 1
        summary = run_test(test_dir)
        if summary.analysis_outcome == "SUCCESS":
            total_analyzed += 1
        if "SUCCESS" in summary.repair_outcome:
            total_repaired += 1

        result_stat.append(summary.result_stat)

        print(f"Test:{test_dir:100}\t analysis={summary.analysis_outcome} \t repair={summary.repair_outcome}")

    print("Test completed\n")
    print(f"Total tests executed: {total_test}")
    print(f"Total tests analyzed: {total_analyzed}({total_test - total_analyzed})")
    print(f"Total tests repaired: {total_repaired}({total_test - total_repaired})")
    write_as_json(result_stat, summary_path)

    # copy across log files
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


def main() -> None:
    parser = argparse.ArgumentParser("runs the HiFix test suite")
    parser.add_argument("--persist-logs", action="store_true", help="copies log files to the mounted logs directory")
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
