#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

BUILD_PATH=${GITHUB_WORKSPACE}/build
DYNAMORIO_ROOT_PATH=${GITHUB_WORKSPACE}/dynamorio

echo -e "Prepare build directory directory .."
mkdir ${BUILD_PATH}
echo -e "Enter \033[34m${BUILD_PATH}\033[0m .."
# enter BUILD_PATH
cd ${BUILD_PATH}
# run cmake
echo -e "Running cmake .."
cmake ${DYNAMORIO_ROOT_PATH} \
        -DBUILD_DOCS=OFF \
        -DBUILD_SAMPLES=OFF \
        -DBUILD_TESTS=OFF \
        -DCMAKE_C_COMPILER=gcc

# start make
echo -e "Running make .."
make -j