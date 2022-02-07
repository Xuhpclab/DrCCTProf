#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2022 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

for i in "$@"; do
  case $i in
    --debug=*)
      DEBUG="${i#*=}"
      shift # past argument=value
      ;;
    -*|--*)
      echo "Unknown option $i"
      exit 1
      ;;
    *)
      ;;
  esac
done

CUR_DIR=$(cd "$(dirname "$0")";pwd)

PLATFORM=$(uname -m)
IS_ARM=false
IS_X86=false
if [ $PLATFORM == 'x86_64' ]; then
    IS_X86=true
fi
if [ $PLATFORM == 'aarch64' ]; then
    IS_ARM=true
fi

if [[ "$IS_X86" == "false" && "$IS_ARM" == "false" ]]; then
    echo -e "NOT support platform $PLATFORM"
    exit -1
fi

echo -e "Prepare test apps .."
TEST_APPS_ROOT=$CUR_DIR/../../test_apps
TEST_APP1_FULL_PATH=$TEST_APPS_ROOT/build/test_app_cct
TEST_APP2_FULL_PATH=$TEST_APPS_ROOT/build/test_app_multithread
TEST_APP3_FULL_PATH=$TEST_APPS_ROOT/build/test_app_reuse
TEST_APP4_FULL_PATH=$TEST_APPS_ROOT/build/test_app_signal
$TEST_APPS_ROOT/build.sh

DRRUN=$CUR_DIR/../../build/bin64/drrun
if [ "$DEBUG" == "true" ]; then
    DRRUN=$CUR_DIR/../../build_debug/bin64/drrun
fi

DEBUG_FLAG=
if [ "$DEBUG" == "true" ]; then
    DEBUG_FLAG=-debug
fi

ARM_SPECIAL_FLAG=
if [ "$IS_ARM" == "true" ]; then
    ARM_SPECIAL_FLAG=-unsafe_build_ldstex
fi

LOG_PATH=$CUR_DIR/../../logs
if [ ! -d $LOG_PATH ]; then
    mkdir $LOG_PATH
fi

echo -e "\033[32mStart test...\033[0m"
set +euo pipefail
cd $LOG_PATH

echo -e "\033[32m-----Testing Dynamorio---------\033[0m"
$DRRUN -- echo hi > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m----------Test 1 (null tool single thread)---------\033[0m"
$DRRUN $DEBUG_FLAG $ARM_SPECIAL_FLAG -t all_instr_cct -- $TEST_APP1_FULL_PATH > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m----------Test 2 (null tool multithread)---------\033[0m"
$DRRUN $DEBUG_FLAG $ARM_SPECIAL_FLAG -t all_instr_cct -- $TEST_APP2_FULL_PATH > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m----------Test 3 (insCount tool single thread)---------\033[0m"
$DRRUN $DEBUG_FLAG $ARM_SPECIAL_FLAG -t instr_statistics -- $TEST_APP1_FULL_PATH > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m----------Test 4 (insCount tool multithread)---------\033[0m"
$DRRUN $DEBUG_FLAG $ARM_SPECIAL_FLAG -t instr_statistics -- $TEST_APP2_FULL_PATH > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m----------Test 5 (reuse distance tool single thread)---------\033[0m"
$DRRUN $DEBUG_FLAG $ARM_SPECIAL_FLAG -t reuse_distance -- $TEST_APP3_FULL_PATH > /dev/null &&
    echo -e "\033[32m----------PASSED---------\033[0m" ||
        (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)

echo -e "\033[32m*************************************************\033[0m"
echo -e "\033[32m************* ALL TESTS Finished ****************\033[0m"
echo -e "\033[32m*************************************************\033[0m"