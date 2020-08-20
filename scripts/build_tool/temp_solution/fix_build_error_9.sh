#! /bin/bash

# **********************************************************
# Copyright (c) 2020 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

BUILD_DIR=$1

echo "fix build error 9"
python3 $CUR_DIR/flags_make_autofix.py $BUILD_DIR/ext/drwrap/CMakeFiles/drwrap.dir/flags.make
python3 $CUR_DIR/flags_make_autofix.py $BUILD_DIR/core/CMakeFiles/dynamorio.dir/flags.make
python3 $CUR_DIR/flags_make_autofix.py $BUILD_DIR/core/CMakeFiles/dynamorio_static.dir/flags.make