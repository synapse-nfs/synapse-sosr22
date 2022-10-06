#!/usr/bin/python3

import os
import re

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))

files = [
    {
        "in": [
            f"{CURRENT_DIR}/churn-1000000-fpm-min-cpu-load.dat",
            f"{CURRENT_DIR}/churn-10000000-fpm-min-cpu-load.dat",
            f"{CURRENT_DIR}/churn-100000000-fpm-min-cpu-load.dat",
        ],
        "out": f"{CURRENT_DIR}/churn-min-cpu-load.tsv"
    },
    {
        "in": [
            f"{CURRENT_DIR}/churn-1000000-fpm-min-resources.dat",
            f"{CURRENT_DIR}/churn-10000000-fpm-min-resources.dat",
            f"{CURRENT_DIR}/churn-100000000-fpm-min-resources.dat",
        ],
        "out": f"{CURRENT_DIR}/churn-min-resources.tsv"
    },
    {
        "in": [
            f"{CURRENT_DIR}/churn-1000000-fpm-max-throughput.dat",
            f"{CURRENT_DIR}/churn-10000000-fpm-max-throughput.dat",
            f"{CURRENT_DIR}/churn-100000000-fpm-max-throughput.dat",
        ],
        "out": f"{CURRENT_DIR}/churn-max-throughput.tsv"
    },
]

cpu_load_baseline = None
for f in files:
    data = []

    for in_file in f["in"]:
        with open(in_file, "r") as fp:
            sent_to_controller = 0
            cpu_load = 0
            churn = int(in_file.split('churn')[1].split('-')[1])

            if churn < 1e6:
                continue
            else:
                churn = f'{int(churn/1000000)}M'

            for line in fp:
                line = line.rstrip()
                line = line.lower()
                
                if "sent to controller" in line:
                    line = re.sub(' +', ' ', line)
                    cpu_load += int(line.split(' ')[3]) * 3 # operations: rx, table write, tx
                    line = line.split('(')[1]
                    sent_to_controller = line.split('%')[0]
                
                elif "digests" in line:
                    line = re.sub(' +', ' ', line)
                    line = line.split('(')[0]
                    cpu_load += int(line.split(' ')[2]) * 2 # operations: rx, table write
            
            if "churn-1000000-fpm-min-cpu-load" in in_file:
                cpu_load_baseline = cpu_load
            
            data.append((churn, sent_to_controller, cpu_load))

    assert cpu_load_baseline

    _data = []
    for i, d in enumerate(data):
        _data.append((d[0], d[1], d[2] / cpu_load_baseline))
    data = _data

    with open(f["out"], "w") as fp:
        fp.write("# churn (fpm) \t controller traffic (%)\n")
        for d in data:
            fp.write(f"{d[0]}\t{d[1]}\t{d[2]}\n")