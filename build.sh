#! /bin/bash

set -euo pipefail

CUR_DIR=$(pwd)

TEMP_MAKE_FILE=${CUR_DIR}/CMakeLists.temp
SRC_PATH=${CUR_DIR}/src
TEST_CLIENTS_SRC_ROOT_PATH=${CUR_DIR}/tests
TEST_CLIENTS=$(ls ${CUR_DIR}/tests)
DYNAMORIO_ROOT_PATH=${CUR_DIR}/dynamorio
DYNAMORIO_EXT_PATH=${DYNAMORIO_ROOT_PATH}/ext
DYNAMORIO_CLIENT_PATH=${DYNAMORIO_ROOT_PATH}/clients

#=============================================================================
echo "Linking source files and cmakefiles.."
# link drcctlib src to dynamorio ext path
rm -rf ${DYNAMORIO_EXT_PATH}/drcctlib
ln -s ${SRC_PATH} ${DYNAMORIO_EXT_PATH}/drcctlib

# link template cmakelists to dynamorio ext path
rm -rf ${DYNAMORIO_EXT_PATH}/CMakeLists.txt
ln -s  ${TEMP_MAKE_FILE}   ${DYNAMORIO_EXT_PATH}/CMakeLists.txt

# link drcctlib test to dynamorio clients path
for TEST_CLIENT in ${TEST_CLIENTS}
do
    rm -rf ${DYNAMORIO_CLIENT_PATH}/${TEST_CLIENT}
    ln -s ${TEST_CLIENTS_SRC_ROOT_PATH}/${TEST_CLIENT} ${DYNAMORIO_CLIENT_PATH}/${TEST_CLIENT}
done

#=============================================================================

echo "Prepare build directory and log directory.."
# init logs directory and the name of next make log file
TIMESTAMP=$(date +%s)
BUILD_LOG_PATH=${CUR_DIR}/logs
if [ ! -d ${BUILD_LOG_PATH} ]; then
    mkdir ${BUILD_LOG_PATH}
fi
MAKE_LOG_FILE=${BUILD_LOG_PATH}/make.log.${TIMESTAMP}
CMAKE_LOG_FILE=${BUILD_LOG_PATH}/cmake.log.${TIMESTAMP}

# init build path and go to build path
DYNAMORIO_BUILD_PATH=${DYNAMORIO_ROOT_PATH}/build
rm -rf ${DYNAMORIO_BUILD_PATH}
mkdir ${DYNAMORIO_BUILD_PATH}

#=============================================================================
echo -e "Enter \033[34m${DYNAMORIO_BUILD_PATH}\033[0m.."
# enter DYNAMORIO_BUILD_PATH
cd ${DYNAMORIO_BUILD_PATH}

echo -e "Running Cmake..(See \033[34m${CMAKE_LOG_FILE}\033[0m for detail)"
# run cmake
cmake .. >${CMAKE_LOG_FILE} 2>&1

echo -e "Running make..(See \033[34m${MAKE_LOG_FILE}\033[0m for detail)"
# start make
make -j >${MAKE_LOG_FILE} 2>&1

echo -e "Leave \033[34m${DYNAMORIO_BUILD_PATH}\033[0m.."
# leave DYNAMORIO_BUILD_PATH
cd ${CUR_DIR}

echo -e "\033[32m Build successfully! \033[0m"

DRRUN_DIRECTORY=${DYNAMORIO_BUILD_PATH}/bin64

set +euo pipefail
cd ${BUILD_LOG_PATH}
echo "-----Testing Dynamorio---------" && ${DRRUN_DIRECTORY}/drrun echo hi > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
echo "-----Test 1---------" && ${DRRUN_DIRECTORY}/drrun -t drcctlib_client -- echo hi > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
echo "-----Test 2---------" && ${DRRUN_DIRECTORY}/drrun -t drcctlib_client_mem_only -- echo hi > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
echo "-----Test 3---------" && ${DRRUN_DIRECTORY}/drrun -t drcctlib_data_centric -- ls > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
echo "-----Test 4---------" && ${DRRUN_DIRECTORY}/drrun -t drcctlib_data_centric_tree_based -- ls > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
echo "-----Test 5---------" && ${DRRUN_DIRECTORY}/drrun -t drcctlib_deadspy -- ls > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
# echo "-----Test 6---------" && ${DRRUN_DIRECTORY}/drrun -t drcctlib_deadspy -- echo hi > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
# echo "-----Test 7---------" && ${DRRUN_DIRECTORY}/drrun -t drcctlib_reader -- echo hi > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
# echo "-----Test 8---------" && ${DRRUN_DIRECTORY}/drrun -t drcctlib_data_centric -- echo hi > /dev/null && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
echo "*************************************************"
echo "************* ALL TESTS PASSED ******************"
echo "*************************************************"