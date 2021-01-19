#! /bin/bash

# **********************************************************
# Copyright (c) 2020 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

GCC_VERSION=$($CUR_DIR/../../scripts/build_tool/gcc_version.sh)
DISABLE_WARNINGS_MIN_GCC_VERSION=10
DISABLE_WARNINGS=
if [ "$GCC_VERSION" -ge "$DISABLE_WARNINGS_MIN_GCC_VERSION" ] ; then
    DISABLE_WARNINGS=-DDISABLE_WARNINGS=ON
fi

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
        -DCMAKE_C_COMPILER=gcc \
        $DISABLE_WARNINGS

# temp solution to build_error(#9)
CMAKE_VERSION=$($CUR_DIR/../../scripts/build_tool/cmake_version.sh)
BUILD_ERROR_MIN_CMAKE_VERSION="3.18"
NEED_FIX=0
if [ ${CMAKE_VERSION%.*} -eq ${BUILD_ERROR_MIN_CMAKE_VERSION%.*} ] ; then
    if [ ${CMAKE_VERSION#*.} -ge ${BUILD_ERROR_MIN_CMAKE_VERSION#*.} ] ; then
        NEED_FIX=1
    fi
elif [ ${CMAKE_VERSION%.*} -gt ${BUILD_ERROR_MIN_CMAKE_VERSION%.*} ] ; then
    NEED_FIX=1
fi
if [ ${NEED_FIX} -eq 1 ] ; then
    $CUR_DIR/../../scripts/build_tool/temp_solution/fix_build_error_9.sh $BUILD_PATH
fi

# start make
echo -e "Running make .. (See \033[34m$MAKE_LOG_FILE\033[0m for detail)"
make