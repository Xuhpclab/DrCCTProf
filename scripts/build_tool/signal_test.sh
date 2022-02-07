#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2022 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

DEBUG=false
if [ "$1" == "-DEBUG" ]; then
    DEBUG=true
fi

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


cd $LOG_PATH
echo -e "\033[32m----------Test signal (null tool)---------\033[0m"
$DRRUN $DEBUG_FLAG $ARM_SPECIAL_FLAG -t drcctlib_all_instr_cct -- $TEST_APP4_FULL_PATH