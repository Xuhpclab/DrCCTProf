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

TIMESTAMP=$(date +%s)
BUILD_PATH=$CUR_DIR/../../build
if [ "$DEBUG_MODE" == "true" ] ; then
    BUILD_PATH=$CUR_DIR/../../build_debug
fi
LOG_PATH=$CUR_DIR/../../logs
DYNAMORIO_ROOT_PATH=$CUR_DIR/../../dynamorio

CMAKE_LOG_FILE=$LOG_PATH/cmake.log.$TIMESTAMP
MAKE_LOG_FILE=$LOG_PATH/make.log.$TIMESTAMP
if [ "$DEBUG_MODE" == "true" ] ; then
    CMAKE_LOG_FILE=$LOG_PATH/cmake_debug.log.$TIMESTAMP
    MAKE_LOG_FILE=$LOG_PATH/make_debug.log.$TIMESTAMP
fi

echo -e "Prepare build directory and log directory .."
rm -rf $BUILD_PATH
mkdir $BUILD_PATH
if [ ! -d $LOG_PATH ]; then
    mkdir $LOG_PATH
fi

echo -e "Enter \033[34m$BUILD_PATH\033[0m .."
# enter BUILD_PATH
cd $BUILD_PATH

# run cmake
echo -e "Running Cmake .. (See \033[34m$CMAKE_LOG_FILE\033[0m for detail)"
if [ "$DEBUG_MODE" == "true" ] ; then
    cmake $DYNAMORIO_ROOT_PATH \
        -DDEBUG=ON \
        -DINTERNAL=ON \
        -DBUILD_DOCS=OFF \
        -DBUILD_SAMPLES=OFF \
        -DBUILD_TESTS=OFF \
        -DCMAKE_C_COMPILER=gcc >$CMAKE_LOG_FILE 2>&1 && \
        echo -e "\033[32m Cmake successfully! \033[0m" || (echo -e "\033[31m Cmake fail! \033[0m"; exit -1)
else
    cmake $DYNAMORIO_ROOT_PATH \
        -DBUILD_DOCS=OFF \
        -DBUILD_SAMPLES=OFF \
        -DBUILD_TESTS=OFF \
        -DCMAKE_C_COMPILER=gcc >$CMAKE_LOG_FILE 2>&1 && \
        echo -e "\033[32m Cmake successfully! \033[0m" || (echo -e "\033[31m Cmake fail! \033[0m"; exit -1)
fi

# start make
echo -e "Running make .. (See \033[34m$MAKE_LOG_FILE\033[0m for detail)"
make -j >$MAKE_LOG_FILE 2>&1 && echo -e "\033[32m Make successfully! \033[0m" || (echo -e "\033[31m Make fail! \033[0m"; exit -1)
