#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)
MODE=-RELEASE
# MODE=-DEBUG
DEBUG_MODE=false
if [ "$MODE" == "-DEBUG" ]; then
    DEBUG_MODE=true
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

DRRUN=$CUR_DIR/../../build/bin64/drrun
if [ "$DEBUG_MODE" == "true" ]; then
    DRRUN=$CUR_DIR/../../build_debug/bin64/drrun
fi

DEBUG_FLAG=
if [ "$DEBUG_MODE" == "true" ]; then
    DEBUG_FLAG=-debug
fi

ARM_SPECIAL_FLAG=
if [ "$IS_ARM" == "true" ]; then
    ARM_SPECIAL_FLAG=-unsafe_build_ldstex
fi

CLIENT=$1
APP_FULL_PATH=$2
APP_ARG1=$3
APP_ARG2=$4
APP_ARG3=$5
APP_ARG4=$6
APP_ARG5=$7
APP_ARG6=$8
APP_ARG7=$9
APP_ARG8=${10}

echo "$DRRUN $DEBUG_FLAG $ARM_SPECIAL_FLAG -t $CLIENT -- $APP_FULL_PATH $APP_ARG1 $APP_ARG2 $APP_ARG3 $APP_ARG4 $APP_ARG5 $APP_ARG6 $APP_ARG7 $APP_ARG8"
$DRRUN $DEBUG_FLAG $ARM_SPECIAL_FLAG -t $CLIENT -- $APP_FULL_PATH $APP_ARG1 $APP_ARG2 $APP_ARG3 $APP_ARG4 $APP_ARG5 $APP_ARG6 $APP_ARG7 $APP_ARG8
