#! /bin/bash

# set -euo pipefail
./run_null.sh ../appsamples/build/sample_cct
./run_cct_ins_counting.sh ../appsamples/build/sample_cct
./run_cct_all_ins.sh ../appsamples/build/sample_cct
./run_cct_mem.sh ../appsamples/build/sample_cct
./run_cct_mem_with_datatcentric.sh ../appsamples/build/sample_cct
./run_cct_memory_with_data_centric_with_search.sh ../appsamples/build/sample_cct