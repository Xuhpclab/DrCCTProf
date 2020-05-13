#! /bin/bash
CUR_DIR=$(cd "$(dirname "$0")";pwd)
# set -euo pipefail
${CUR_DIR}/run_null.sh ${CUR_DIR}/../appsamples/build/sample_cct
${CUR_DIR}/run_cct_ins_counting.sh ${CUR_DIR}/../appsamples/build/sample_cct
${CUR_DIR}/run_cct_all_ins.sh ${CUR_DIR}/../appsamples/build/sample_cct
${CUR_DIR}/run_cct_mem.sh ${CUR_DIR}/../appsamples/build/sample_cct
${CUR_DIR}/run_cct_mem_with_datatcentric.sh ${CUR_DIR}/../appsamples/build/sample_cct
${CUR_DIR}/run_cct_memory_with_data_centric_with_search.sh ${CUR_DIR}/../appsamples/build/sample_cct