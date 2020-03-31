#! /bin/bash

set -euo pipefail

CUR_DIR=$(pwd)
SRC=${CUR_DIR}/src
BUILD=${CUR_DIR}/build
if [ ! -d ${BUILD} ]; then
    mkdir ${BUILD}
fi
# build sample1
g++ -g ${SRC}/sample/sample.cxx -o ${BUILD}/sample 
g++ -g ${SRC}/sample/sample_cct.cxx -o ${BUILD}/sample_cct 
g++ -g ${SRC}/sample/sample_multithread.cxx -o ${BUILD}/sample_multithread -pthread
g++ -g ${SRC}/sample/sample_reuse.cxx -o ${BUILD}/sample_reuse
