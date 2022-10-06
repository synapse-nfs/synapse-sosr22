#!/usr/bin/python3

import os
import re

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))

files = [
    {
        "in":  f"{CURRENT_DIR}/zipf-min-resources.dat",
        "out": f"{CURRENT_DIR}/zipf-min-resources.tsv"
    },
    {
        "in":  f"{CURRENT_DIR}/zipf-min-cpu-load.dat",
        "out": f"{CURRENT_DIR}/zipf-min-cpu-load.tsv"
    },
    {
        "in":  f"{CURRENT_DIR}/zipf-max-throughput.dat",
        "out": f"{CURRENT_DIR}/zipf-max-throughput.tsv"
    },
]

cpu_load_baseline = None
for f in files:
    in_file = f["in"]
    out_file = f["out"]

    data = []

    with open(in_file, "r") as fp:
        approach = 0
        sent_to_controller = 0
        cpu_load = 0

        approach = in_file.split('/')[-1]    # filename
        approach = approach.split('.')[0]    # no extension
        approach = approach.split('zipf-')[1] # approach

        for line in fp:
            line = line.rstrip()
            line = line.lower()
            
            if "sent to controller" in line:
                line = re.sub(' +', ' ', line)
                cpu_load += int(line.split(' ')[3]) * 3 # operations: rx, table write, tx
                line = line.split('(')[1]
                sent_to_controller = float(line.split('%')[0])
            
            if "digests" in line and approach == "max-throughput":
                line = re.sub(' +', ' ', line)
                line = line.split('(')[0]
                cpu_load += int(line.split(' ')[2]) * 2 # operations: rx, table write
        
        if approach == "min-resources":
            cpu_load_baseline = cpu_load
            cpu_load = 1
        else:
            cpu_load = cpu_load / cpu_load_baseline
        
        data.append((approach, sent_to_controller, cpu_load))

    with open(out_file, "w") as fp:
        fp.write("# approach\tcontroller traffic (%)\tcpu load\n")
        for d in data:
            fp.write(f"\"{d[0]}\"\t{d[1]}\t{d[2]}")