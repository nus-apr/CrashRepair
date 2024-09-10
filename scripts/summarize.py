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

import yaml

correct_patch_text = {
    "CVE-2017-15025": "if (!((lh.line_range != 0))) { exit(1); } ",
    "gnubug-19784": "(i < size && sieve[++i] == 0) && (((i + 1) < size))",
    "CVE-2016-8691": "if (!((cmpt->hstep != 0))) { exit(1); } ",
    "CVE-2016-9557": "if (!(((cmptparm->width * cmptparm->height) <= (9223372036854775807 / ((7 + (cmptparm->width * (cmptparm->height * cmptparm->prec))) + 7))))) { exit(1); } ",
    "CVE-2016-5844": "if (!((2048 <= (2147483647 / vd->location)))) { exit(1); } ",
    "CVE-2012-2806": "if (!(((8 * i) < 32))) { return -1; } ",
    "CVE-2017-15232": "if (!((output_buf != 0))) { exit(1); } ",
    "CVE-2016-9264": "if (!(((4 * samplerate_idx) < 12))) { exit(1); } ",
    "CVE-2018-8806": "if (!(((8 * act->p.Constant8) < crepair_size(pool)))) { return \"\"; } ",
    "CVE-2018-8964": "if (!(((8 * act->p.Constant8) < crepair_size(pool)))) { exit(0); } ",
    "CVE-2016-10092": "stripsize",
    "CVE-2016-10272": "stripsize",
    "CVE-2016-3186": "((count = getc(infile)) && count <= 255) && ((count >= 0))",
    "CVE-2016-5314": "if (!((sp->tbuf < (crepair_base(sp->tbuf) + crepair_size(sp->tbuf))))) { return 0; } ",
    "CVE-2016-5321": "if (!(((8 * s) < 64))) { return -1; } ",
    "CVE-2016-9532": "if (!(((rowsperstrip * bytes_per_sample) <= (4294967295 / (width + 1))))) { exit(1); } ",
    "CVE-2017-7595": "if (!(((sp->v_sampling * 8) != 0))) { return 0; } ",
    "CVE-2012-5134": "(((len - 1) < buf_size)) && (buf[len - 1] == 0x20)",
    "CVE-2016-1838": "(ctxt->input->cur[tlen] == '>') && (((ctxt->input->cur + tlen) < (crepair_base(ctxt->input->cur) + crepair_size(ctxt->input->cur))))",
    "CVE-2017-5969": "((content->c2 != 0)) && ((content->c2->type == XML_ELEMENT_CONTENT_OR) ||\n        ((content->c2->type == XML_ELEMENT_CONTENT_SEQ) &&\n (content->c2->ocur != XML_ELEMENT_CONTENT_ONCE)))",
    "CVE-2013-7437": "if (!((0 < (bm->dy * bm->h)))) { return; } ",
    "CVE-2017-5975": "if (!((0 != header))) { return 0; } "
}


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
    fix_loc_count_list = []
    patch_space_size_list = []
    patch_enumeration_count_list = []
    patch_plausible_count_list = []
    patch_noncomp_list = []
    top_1_dist_list = []
    top_5_dist_list = []
    top_10_dist_list = []

    for f in tarfiles:
        dir_result = str(f).replace(".tar.gz", "")
        run_id = str(dir_result).split("-")[-2]

        if not os.path.isdir(dir_result):
            os.system(f" tar -xf {f}")

        report_file = f"{dir_result}/output/report.json"
        if os.path.isfile(report_file):
            report_json = read_json(report_file)

        run_info = dict()

        if "fuzzer" in report_json:
            # run_info['fuzzer'] = report_json['fuzzer']
            passing_test = int(report_json['fuzzer']['summary']['num-tests']['passing'])
            crashing_test = int(report_json['fuzzer']['summary']['num-tests']['crashing'])
            total_passing_test += passing_test
            total_crashing_test += crashing_test
        else:
            passing_test = "NA"
            crashing_test = "NA"

        candidate_dist = dict()
        candidate_text = dict()
        candidate_op = dict()
        fix_loc_dist = dict()

        if "analysis" in report_json:
            fix_loc_list = report_json["analysis"]["fix-locations"]
            for loc in fix_loc_list:
                fix_loc_dist[loc["location"]] = loc["distance"]

        if "generation" in report_json:
            count_candidates = report_json["generation"]["summary"]["num-candidates"]
            candidate_list = report_json["generation"]["candidates"]
            for p in candidate_list:
                candidate_dist[p["id"]] = fix_loc_dist[p["location"]]
                candidate_text[p["id"]] = p["replacements"][0]["text"]
                repair_op = p["operator"]
                candidate_op[p["id"]] = repair_op
                if repair_op not in operator_stats:
                    operator_stats[repair_op] = {"candidates": 0, "plausible": 0, "subjects": set()}
                operator_stats[repair_op]["candidates"] += 1

        else:
            count_candidates = "NA"
        if "validation" in report_json:
            validation_info = report_json["validation"]
            count_evaluations = validation_info["summary"]["num-patches-evaluated"]
            count_plausible = validation_info["summary"]["num-repairs-found"]
            count_fix_locs = report_json["analysis"]["summary"]["num-fix-locations"]
            count_non_compiling = validation_info["summary"]["num-compilation-failures"]
            overfitting_patches = []
            plausible_patches = validation_info["repairs"]

            avg_dist_info = []
            if plausible_patches:
                for p_id in plausible_patches:
                    operator_stats[candidate_op[p_id]]["subjects"].add(bug_id)
                    operator_stats[candidate_op[p_id]]["plausible"] += 1
                for n in [1,5,10]:
                    dist_list = []
                    for p_id in plausible_patches[:n]:
                        dist_list.append(int(candidate_dist[p_id]))
                    avg_dist_info.append(mean(dist_list))

            for validation in validation_info["evaluations"]:
                patch_id = validation["patch-id"]
                results = validation["tests"]
                t_pass = results["passed"]
                t_fail = results["failed"]
                if int(t_fail) > 0 and int(t_pass) > 0:
                    overfitting_patches.append(patch_id)

            rank = 0
            if bug_id in correct_patch_text:
                _text = correct_patch_text[bug_id]
                for num, p_id in enumerate(plausible_patches):
                    if _text in candidate_text[p_id]:
                        rank = num + 1
                        break
        else:
            count_evaluations = "NA"
            count_plausible = "NA"
            size_space = "NA"
            count_non_compiling = "NA"
            count_fix_locs = "NA"
            overfitting_patches = []
            avg_dist_info = []
            rank = "NA"

        run_info["count_candidates"] = count_candidates
        run_info["count_evaluations"] = count_evaluations
        run_info["count_plausible"] = count_plausible
        run_info["count_fix_locs"] = count_fix_locs
        run_info["count_non_compiling"] = count_non_compiling
        if avg_dist_info:
            run_info["dist_top_1"] = avg_dist_info[0]
            run_info["dist_top_5"] = avg_dist_info[1]
            run_info["dist_top_10"] = avg_dist_info[2]
        else:
            run_info["dist_top_1"] = "NA"
            run_info["dist_top_5"] = "NA"
            run_info["dist_top_10"] = "NA"

        run_info["passing_tests"] = passing_test
        run_info["crashing_tests"] = crashing_test
        run_info["overfitting_count"] = len(overfitting_patches)
        run_info["overfitting_patches"] = overfitting_patches
        run_info["rank"] = rank


        print("\t", run_id, "passing", passing_test, "failing", crashing_test, "overfitting", len(overfitting_patches),
              "plausible", count_plausible)
        subject_results = dict()
        if subject in aggregated_results:
            subject_results = aggregated_results[subject]

        bug_results = dict()
        if bug_id in subject_results:
            bug_results = subject_results[bug_id]

        bug_results[run_id] = run_info
        subject_results[bug_id] = bug_results
        aggregated_results[subject] = subject_results
        run_info["subject"] = subject
        run_info["bug_id"] = bug_id
        run_info["run_id"] = run_id
        del run_info["overfitting_patches"]
        csv_results.append(run_info)

    os.chdir("..")

for op in operator_stats:
    op_info = operator_stats[op]
    op_sub_count = len(op_info["subjects"])
    op_info["subjects"] = op_sub_count
    operator_stats[op] = op_info

write_as_json(aggregated_results, "aggregated.json")
write_as_json(csv_results, "csv.json")
write_as_json(operator_stats, "operators.json")