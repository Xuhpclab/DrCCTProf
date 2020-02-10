#! /bin/bash

# set -euo pipefail

CUR_DIR=$(pwd)
BUILD_PATH=${CUR_DIR}/build


echo "Prepare build directory and log directory.."
# init logs directory and the name of next make log file
TIMESTAMP=$(date +%s)
BUILD_LOG_PATH=${CUR_DIR}/logs
if [ ! -d ${BUILD_LOG_PATH} ]; then
    mkdir ${BUILD_LOG_PATH}
fi
MAKE_LOG_FILE=${BUILD_LOG_PATH}/make.log
DR_LOG_FILE=${BUILD_LOG_PATH}/dr.log

echo -e "Enter \033[34m${BUILD_PATH}\033[0m.."
# enter BUILD_PATH
cd ${BUILD_PATH}


echo -e "Running make..(See \033[34m${MAKE_LOG_FILE}\033[0m for detail)"
# start make
make -j >${MAKE_LOG_FILE} 2>&1
# cmake --build . --config Debug -- -j 74 >${MAKE_LOG_FILE} 2>&1

echo -e "\033[32m Rebuild successfully! \033[0m"

RUN_DIRECTORY=${BUILD_PATH}/bin64

# set +euo pipefail
cd ${BUILD_LOG_PATH}
# gdb ${RUN_DIRECTORY}/drrun
# echo "-----Testing Dynamorio---------" && ${RUN_DIRECTORY}/drrun echo hi > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
echo "-----Test 1---------" && ${RUN_DIRECTORY}/drrun -t drcctlib_client -- ${CUR_DIR}/appsamples/build/sample1 > ${DR_LOG_FILE} 2>&1
# echo "-----Test 2---------" && ${RUN_DIRECTORY}/drrun -t drcctlib_client_mem_only -- ${CUR_DIR}/appsamples/build/sample1.o > ${DR_LOG_FILE} 2>&1 && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
# echo "-----Test 3---------" && ${RUN_DIRECTORY}/drrun -t drcctlib_data_centric -- ${CUR_DIR}/appsamples/build/sample1.o > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
# echo "-----Test 4---------" && ${RUN_DIRECTORY}/drrun -t drcctlib_data_centric_tree_based -- ls > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
# echo "-----Test 5---------" && ${RUN_DIRECTORY}/drrun -t drcctlib_deadspy -- ls > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
# echo "-----Test 6---------" && ${RUN_DIRECTORY}/drrun -t drcctlib_deadspy -- echo hi > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
# echo "-----Test 7---------" && ${RUN_DIRECTORY}/drrun -t drcctlib_reader -- echo hi > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
# echo "-----Test 8---------" && ${RUN_DIRECTORY}/drrun -t drcctlib_data_centric -- echo hi > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
