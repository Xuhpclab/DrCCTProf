#! /bin/bash

# set -euo pipefail
./run_null.sh ../appsamples/build sample_cct
./run_cct_call_return.sh ../appsamples/build sample_cct
./run_cct_datacentric_only.sh ../appsamples/build sample_cct
./run_cct_all_ins.sh ../appsamples/build sample_cct
./run_cct_all_ins_with_data_centric.sh ../appsamples/build sample_cct
./run_cct_mem.sh ../appsamples/build sample_cct
./run_cct_mem_with_datatcentric.sh ../appsamples/build sample_cct
./run_cct_ins_counting.sh ../appsamples/build sample_cct
