#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

DEBUG_MODE=false
if [ "$1" == "-DEBUG" ] ; then
    DEBUG_MODE=true
fi

BUILD_PATH=$CUR_DIR/../../build
if [ "$DEBUG_MODE" == "true" ]; then
    BUILD_PATH=$CUR_DIR/../../build_debug
fi
echo -e "Remove \033[34m$BUILD_PATH\033[0m .."
if [ -d $BUILD_PATH ]; then
    rm -rf $BUILD_PATH
fi


