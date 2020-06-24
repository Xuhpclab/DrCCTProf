#! /bin/bash

CUR_DIR=$(cd "$(dirname "$0")";pwd)

DEBUG_MODE=false
if [ "$1" == "-DEBUG" ] ; then
    DEBUG_MODE=true
fi

TIMESTAMP=$(date +%s)
BUILD_PATH=${CUR_DIR}/../../build
if [ "$DEBUG_MODE" == "true" ] ; then
    BUILD_PATH=${CUR_DIR}/../../build_debug
fi
LOG_PATH=${CUR_DIR}/../../logs

CMAKE_LOG_FILE=${LOG_PATH}/cmake.log.${TIMESTAMP}
MAKE_LOG_FILE=${LOG_PATH}/make.log.${TIMESTAMP}
if [ "$DEBUG_MODE" == "true" ] ; then
    CMAKE_LOG_FILE=${LOG_PATH}/cmake_debug.log.${TIMESTAMP}
    MAKE_LOG_FILE=${LOG_PATH}/cmake_debug.log.${TIMESTAMP}
fi

echo -e "Enter \033[34m${BUILD_PATH}\033[0m .."
# enter BUILD_PATH
cd ${BUILD_PATH}

# start remake
echo -e "Running remake .. (See \033[34m${MAKE_LOG_FILE}\033[0m for detail)"
make -j >${MAKE_LOG_FILE} 2>&1 && echo -e "\033[32m Remake successfully! \033[0m" || (echo -e "\033[31m Remake fail! \033[0m"; exit -1)