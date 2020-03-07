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

cd ${BUILD_PATH}
echo -e "Running make..(See \033[34m${MAKE_LOG_FILE}\033[0m for detail)"
make -j >${MAKE_LOG_FILE} 2>&1 && echo -e "\033[32m Rebuild successfully! \033[0m" && echo -e "\033[31m Rebuild fail! \033[0m"
RUN_DIRECTORY=${BUILD_PATH}/bin32

SAMPLE_ROOT_DIRECTORY=${CUR_DIR}/appsamples
echo -e "-----Build sample -----" && g++ -g ${SAMPLE_ROOT_DIRECTORY}/src/sample/sample.cxx -pthread -o ${SAMPLE_ROOT_DIRECTORY}/build/sample && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)


cd ${BUILD_LOG_PATH}
for i in 1
do
time ${SAMPLE_ROOT_DIRECTORY}/build/sample
echo -e "-----Test tool-----(See\033[34m${DR_LOG_FILE}\033[0m for detail)"
time ${RUN_DIRECTORY}/drrun -t drcctlib_client -- ${CUR_DIR}/appsamples/build/sample > ${DR_LOG_FILE} 2>&1
done
