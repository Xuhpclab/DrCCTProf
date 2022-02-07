#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2022 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

echo -e "app build clean..."
$CUR_DIR/test_apps/build_clean.sh

echo -e "clean logs..."
$CUR_DIR/scripts/clean_logs.sh

echo -e "make clean..."
$CUR_DIR/scripts/build_tool/make_clean.sh

echo -e "make debug clean..."
$CUR_DIR/scripts/build_tool/make_clean.sh --debug=true

echo -e "clean env config..."
$CUR_DIR/scripts/build_tool/env_clean.sh

echo -e "clean dynamorio patch..."
$CUR_DIR/scripts/build_tool/dr_patch_clean.sh


