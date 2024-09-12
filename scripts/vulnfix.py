import sys
import os
from os import listdir
from os.path import isfile, join, isdir
import csv
import json
import os
from statistics import mean
from typing import Any
from typing import Optional


def read_json(file_path: str) -> Optional[Any]:
    json_data = None
    if os.path.isfile(file_path):
        with open(file_path, "r") as in_file:
            content = in_file.readlines()
            if len(content) > 1:
                content_str = " ".join([l.strip().replace("\n", "") for l in content])
            else:
                content_str = content[0]
            json_data = json.loads(content_str)
    return json_data


def write_as_json(data: Any, output_file_path: str) -> None:
    content = json.dumps(data)
    with open(output_file_path, "w") as out_file:
        out_file.writelines(content)


dir_path = sys.argv[1]
subdirs = [d for d in listdir(dir_path) if isdir(join(dir_path, d))]
os.chdir(dir_path)
aggregated_results = dict()
average_results = dict()
csv_results = []
operator_stats = dict()

for d in subdirs:
    tarfiles = [f for f in listdir(d) if isfile(join(d, f)) and ".tar.gz" in f]
    # print(len(tarfiles), tarfiles)

    total_passing_test = 0
    total_crashing_test = 0

    subject = str(d).split("-")[0]
    bug_id = str(d).replace(subject + "-", "")
    os.chdir(d)
    print(subject, bug_id)

    patch_list = set()
    plausible_count = 0
    eval_count = 0
    for f in tarfiles:
        dir_result = str(f).replace(".tar.gz", "")
        run_id = str(dir_result).split("-")[-2]

        if not os.path.isdir(dir_result):
            os.system(f" tar -xf {f}")
        eval_count += 1
        result_dir = f"{dir_result}/output/result"
        if os.path.isdir(result_dir):
            dir_list = os.listdir(result_dir)
            found_patch = False
            for f in dir_list:
                if ".patch" in f:
                    if not found_patch:
                        plausible_count += 1
                        found_patch = True
                    with open(f"{result_dir}/{f}") as patch_file:
                        patch_diff = patch_file.readlines()
                        path_str = "\n".join(patch_diff[2:])
                        patch_list.add(path_str)

    aggregated_results[bug_id] = {"plausible": plausible_count,
                                  "unique": len(patch_list),
                                  "evaluations": eval_count}
    os.chdir("..")



write_as_json(aggregated_results, "aggregated.json")

