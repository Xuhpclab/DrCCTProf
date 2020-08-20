#! /bin/bash

# **********************************************************
# Copyright (c) 2020 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

echo -e "Prepare test apps .."
TEST_APPS_ROOT=$CUR_DIR/../../test_apps
TEST_APP1_FULL_PATH=$TEST_APPS_ROOT/build/test_app_cct
TEST_APP2_FULL_PATH=$TEST_APPS_ROOT/build/test_app_multithread
TEST_APP3_FULL_PATH=$TEST_APPS_ROOT/build/test_app_reuse
$TEST_APPS_ROOT/build.sh

DRRUN=$CUR_DIR/../../build/bin64/drrun

echo -e "\033[32mStart test...\033[0m"
set +euo pipefail

echo -e "\033[32m-----Testing Dynamorio---------\033[0m"
$DRRUN -- echo hi > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m----------Test 1 (null tool single thread code cache)---------\033[0m"
$DRRUN -t drcctlib_all_instr_cct -- $TEST_APP1_FULL_PATH > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m----------Test 2 (null tool single thread clean call)---------\033[0m"
$DRRUN -t drcctlib_all_instr_cct_no_cache -- $TEST_APP1_FULL_PATH > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m----------Test 3 (null tool multithread code cache)---------\033[0m"
$DRRUN -t drcctlib_all_instr_cct -- $TEST_APP2_FULL_PATH > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m----------Test 4 (null tool multithread clean call)---------\033[0m"
$DRRUN -t drcctlib_all_instr_cct_no_cache -- $TEST_APP2_FULL_PATH > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m----------Test 5 (insCount tool single thread code cache)---------\033[0m"
$DRRUN -t drcctlib_instr_statistics -- $TEST_APP1_FULL_PATH > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m----------Test 6 (insCount tool single thread clean call)---------\033[0m"
$DRRUN -t drcctlib_instr_statistics_clean_call -- $TEST_APP1_FULL_PATH > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m----------Test 7 (insCount tool multithread code cache)---------\033[0m"
$DRRUN -t drcctlib_instr_statistics -- $TEST_APP2_FULL_PATH > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m----------Test 8 (insCount tool multithread clean call)---------\033[0m"
$DRRUN -t drcctlib_instr_statistics_clean_call -- $TEST_APP2_FULL_PATH > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m----------Test 9 (reuse distance tool single thread)---------\033[0m"
$DRRUN -t drcctlib_reuse_distance -- $TEST_APP3_FULL_PATH > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m*************************************************\033[0m"
echo -e "\033[32m************* ALL TESTS Finished ****************\033[0m"
echo -e "\033[32m*************************************************\033[0m"