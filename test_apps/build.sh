#! /bin/bash

# **********************************************************
# Copyright (c) 2020 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

set -euo pipefail

CUR_DIR=$(cd "$(dirname "$0")";pwd)
SRC=${CUR_DIR}/src
BUILD=${CUR_DIR}/build
if [ ! -d ${BUILD} ]; then
    mkdir ${BUILD}
fi

echo -e "\033[32m Start build test apps... \033[0m"
g++ -g ${SRC}/test_app_cct.cpp -o ${BUILD}/test_app_cct
g++ -g ${SRC}/test_app_multithread.cpp -o ${BUILD}/test_app_multithread -pthread
g++ -g ${SRC}/test_app_reuse.cpp -o ${BUILD}/test_app_reuse 
g++ -g ${SRC}/test_app_signal.cpp -o ${BUILD}/test_app_signal
echo -e "\033[32m Build test apps successfully! \033[0m"
