#! /bin/bash

# **********************************************************
# Copyright (c) 2020 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

BUILD_PATH=$CUR_DIR/../../build
DYNAMORIO_ROOT_PATH=$CUR_DIR/../../dynamorio

echo -e "Prepare build directory directory .."
mkdir $BUILD_PATH
echo -e "Enter \033[34m$BUILD_PATH\033[0m .."
# enter BUILD_PATH
cd $BUILD_PATH
# run cmake
echo -e "Running Cmake .. (See \033[34m$CMAKE_LOG_FILE\033[0m for detail)"
cmake $DYNAMORIO_ROOT_PATH \
        -DBUILD_DOCS=OFF \
        -DBUILD_SAMPLES=OFF \
        -DBUILD_TESTS=OFF \
        -DCMAKE_C_COMPILER=gcc
# start make
echo -e "Running make .. (See \033[34m$MAKE_LOG_FILE\033[0m for detail)"
make