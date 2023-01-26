#!/usr/bin/env python3.8
import argparse
import json
import mmap
import multiprocessing
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
    directory: str
    repair_outcome: str
    linter_errors: int
    analysis_outcome: str
    # TODO this should be collapsed into a set of dataclass fields
    result_stat: t.Tuple[t.Any]


def scenario_directories() -> t.List[str]:
    """Returns a list of absolute paths to scenario directories containing a bug.json file"""
    result: t.Set[str] = set()
    for root, _, files in os.walk(dir_path):
        if "bug.json" in files:
            result.add(os.path.abspath(root))
    return sorted(result)


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


def clean(test_dir: str) -> None:
    analysis_dir = os.path.join(test_dir, "analysis")
    shutil.rmtree(analysis_dir, ignore_errors=True)

    # TODO we could run git reset here


def run_linter(test_dir: str) -> int:
    """Runs the linter on the localization.json for a given bug scenario.

    Returns
    -------
    int
        The number of bad fix locations in the localization.json
    """
    command = "crashrepair lint --fix bug.json > linter.log 2>&1"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=test_dir)
    process.wait()

    linter_report_filename = os.path.join(test_dir, "linter-summary.json")

    if not os.path.exists(linter_report_filename):
        return 1

    with open(linter_report_filename, "r") as fh:
        report = json.load(fh)
        return len(report["errors"])


def run_analyze(test_dir: str) -> str:
    clean(test_dir)

    localization_filename = os.path.join(test_dir, "analysis/localization.json")

    analyze_command = "git clean -f; crashrepair analyze bug.json > analyze.log 2>&1"
    process = subprocess.Popen(analyze_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, cwd=test_dir)
    process.wait()
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
    if result == "SUCCESS":
        with open(localization_filename, "r") as fh:
            localization = json.load(fh)
            fix_loc_count = len(localization)
        result = f"{result}({fix_loc_count})"
    return result


def run_repair(test_dir: str) -> str:
    clean(test_dir)

    repair_command = "git clean -f; crashrepair repair --no-fuzz bug.json > repair.log 2>&1"
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
    linter_errors = run_linter(test_dir)
    repair_result = run_repair(test_dir)

    generated_file_list = getListOfFiles(test_dir)
    fix_location_found = len(list(filter(re.compile(".*fix-locations.json").match, generated_file_list)))
    localization_found = len(list(filter(re.compile(".*localization.json").match, generated_file_list)))
    source_map_found = len(list(filter(re.compile(".*source-mapping.json").match, generated_file_list)))
    mutation_found = len(list(filter(re.compile(".*mutations.json").match, generated_file_list)))
    super_mutant_found = len(list(filter(re.compile(".*-mutated").match, generated_file_list)))
    patch_list = list(filter(re.compile(".*.patch").match, generated_file_list))
    repair_generated = len(patch_list)
    repair_patched = False
    repair_compiled = False
    repair_pass_oracle = False

    # validate each candidate patch
    for patch_file_path in patch_list:
        with open(patch_file_path, "r") as p_file:
            buggy_file_path = p_file.readline().split(" ")[-1].replace("\n", "").strip()
            patch_command = f"patch {buggy_file_path} {patch_file_path}"
            process = subprocess.Popen(patch_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, cwd=test_dir)
            process.wait()
            repair_patched = process.returncode == 0

            if not repair_patched:
                continue

            compile_command = "LLVM_COMPILER=clang CC=wllvm CXX=wllvm++ bash build.sh"
            process = subprocess.Popen(compile_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, cwd=test_dir)
            process.wait()
            repair_compiled = process.returncode == 0

            if not repair_compiled:
                continue

            test_command = "bash test.sh"
            process = subprocess.Popen(test_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, cwd=test_dir)
            process.wait()
            repair_pass_oracle = process.returncode == 0

            revert_command = f"patch -R {buggy_file_path} {patch_file_path}"
            process = subprocess.Popen(revert_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, cwd=test_dir)
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
    clean_command = "git clean -f; git checkout HEAD -- ."
    process = subprocess.Popen(clean_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, cwd=test_dir)
    process.wait()

    summary = ScenarioSummary(
        directory=test_dir,
        repair_outcome=repair_result,
        analysis_outcome=analyze_result,
        result_stat=result_stat,
        linter_errors=linter_errors,
    )

    linter_report = f"BAD({summary.linter_errors})" if summary.linter_errors > 0 else "OK"

    print(f"Test:{test_dir:100}\t analysis={summary.analysis_outcome} \tlinter={linter_report} \t repair={summary.repair_outcome}")

    return summary


def copy_logs() -> None:
    """Copies across the log files to the mounted logs directory"""
    for bug_directory in scenario_directories():
        from_analyze_log = os.path.join(bug_directory, "analyze.log")
        from_repair_log = os.path.join(bug_directory, "repair.log")

        rel_test_dir = os.path.relpath(bug_directory, dir_path)
        log_dir = os.path.join("/logs", rel_test_dir)
        to_analyze_log = os.path.join(log_dir, "analyze.log")
        to_repair_log = os.path.join(log_dir, "repair.log")

        os.makedirs(log_dir, exist_ok=True)
        if os.path.isfile(from_analyze_log):
            shutil.copyfile(from_analyze_log, to_analyze_log)
        if os.path.isfile(from_repair_log):
            shutil.copyfile(from_repair_log, to_repair_log)


def run(args: argparse.Namespace) -> None:
    test_dirs = scenario_directories()
    outcomes: t.List[ScenarioSummary] = []

    with multiprocessing.Pool(args.workers) as pool:
        outcomes = pool.map(run_test, test_dirs)

    # compute stats
    total_tests = len(outcomes)
    total_analyzed = sum(1 for outcome in outcomes if outcome.analysis_outcome == "SUCCESS")
    total_repaired = sum(1 for outcome in outcomes if "SUCCESS" in outcome.repair_outcome)
    total_linter_error_scenarios = sum(1 for outcome in outcomes
                                       if outcome.linter_errors > 0)
    total_linter_errors = sum(outcome.linter_errors for outcome in outcomes
                              if "SUCCESS" in outcome.analysis_outcome)
    result_stat = [outcome.result_stat for outcome in outcomes]

    print("Test completed\n")
    print(f"Total tests executed: {total_tests}")
    print(f"Total tests analyzed: {total_analyzed}({total_tests - total_analyzed})")
    print(f"Total tests repaired: {total_repaired}({total_tests - total_repaired})")
    print(f"Total linter errors: {total_linter_errors} in {total_linter_error_scenarios} scenarios")
    write_as_json(result_stat, summary_path)

    copy_logs()


def main() -> None:
    parser = argparse.ArgumentParser("runs the HiFix test suite")
    parser.add_argument("--persist-logs", action="store_true", help="copies log files to the mounted logs directory")
    parser.add_argument(
        "-j",
        type=int,
        default=1,
        dest="workers",
        help="number of workers to use when running tests",
    )
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
