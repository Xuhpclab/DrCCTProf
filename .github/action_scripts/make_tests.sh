#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

echo -e "Prepare test apps .."
TEST_APPS_ROOT=${GITHUB_WORKSPACE}/test_apps
TEST_APP1_FULL_PATH=${TEST_APPS_ROOT}/build/test_app_cct
TEST_APP2_FULL_PATH=${TEST_APPS_ROOT}/build/test_app_multithread
TEST_APP3_FULL_PATH=${TEST_APPS_ROOT}/build/test_app_reuse
${TEST_APPS_ROOT}/build.sh

DRRUN=${GITHUB_WORKSPACE}/build/bin64/drrun

CLIENT_LIST=(
    "drcctlib_all_instr_cct"
    "drcctlib_all_instr_cct_hpc_fmt"
    "drcctlib_all_instr_cct_no_cache"
    "drcctlib_all_instr_cct_with_data_centric"
    "drcctlib_cct_only"
    "drcctlib_cct_only_clean_call"
    "drcctlib_cct_only_no_cache"
    "drcctlib_instr_statistics"
    "drcctlib_instr_statistics_clean_call"
    "drcctlib_instr_statistics_hpc_fmt"
    "drcctlib_memory_only"
    "drcctlib_memory_only_clean_call"
    "drcctlib_memory_with_addr_and_refsize_clean_call"
    "drcctlib_memory_with_data_centric"
    "drcctlib_memory_with_data_centric_clean_call"
    "drcctlib_memory_with_data_centric_with_search"
    "drcctlib_memory_with_data_centric_with_search_clean_call"
    "drcctlib_overhead_test"
    "drcctlib_reuse_distance"
    "drcctlib_reuse_distance_client_cache"
    "drcctlib_reuse_distance_client_cache_hpc_fmt"
    "drcctlib_reuse_distance_hpc_fmt"
    "drcctlib_reuse_distance_mpi"
    "drcctlib_reuse_space_distance"
    "drcctlib_reuse_space_distance_client_cache_hpc_fmt"
    "drcctlib_reuse_space_distance_hpc_fmt"
    "drcctlib_stack_memory_rate"
)
echo -e "\033[32mStart test...\033[0m"
set +euo pipefail

echo -e "\033[32m-----Testing Dynamorio---------\033[0m"
${DRRUN} -- echo hi > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

for client in ${CLIENT_LIST[@]}
do
    echo -e "\033[32m-----Testing ${client}(single thread app)---------\033[0m"
    ${DRRUN} ${DEBUG_FLAG} -t ${client} -- ${TEST_APP1_FULL_PATH} > /dev/null &&
        echo -e "\033[32m----------PASSED---------\033[0m" ||
            (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
    echo -e "\033[32m-----Testing ${client}(multithread app)---------\033[0m"
    ${DRRUN} ${DEBUG_FLAG} -t ${client} -- ${TEST_APP2_FULL_PATH} > /dev/null &&
        echo -e "\033[32m----------PASSED---------\033[0m" ||
            (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
    echo -e "\033[32m-----Testing ${client}(memory redundant app)---------\033[0m"
    ${DRRUN} ${DEBUG_FLAG} -t ${client} -- ${TEST_APP3_FULL_PATH} > /dev/null &&
        echo -e "\033[32m----------PASSED---------\033[0m" ||
            (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
done

echo -e "\033[32m*************************************************\033[0m"
echo -e "\033[32m************* ALL TESTS Finished ****************\033[0m"
echo -e "\033[32m*************************************************\033[0m"