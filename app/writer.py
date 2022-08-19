#! /usr/bin/env python3
# -*- coding: utf-8 -*-


import pickle
import json
import csv
import os
from app import generator, utilities, values, emitter


def write_as_json(data, output_file_path):
    content = json.dumps(data, indent=2)
    with open(output_file_path, 'w') as out_file:
        out_file.writelines(content)


def write_as_pickle(data, output_file_path):
    with open(output_file_path, 'wb') as out_file:
        pickle.dump(data, out_file)

def write_as_csv(fieldnames, rows, output_file_path):
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    with open(output_file_path, 'w', encoding='UTF8', newline='') as out_file:
        writer = csv.DictWriter(out_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)