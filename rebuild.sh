#! /bin/bash

# set -euo pipefail

CUR_DIR=$(cd "$(dirname "$0")";pwd)
BUILD_PATH=${CUR_DIR}/build


echo "Prepare build directory and log directory.."
# init logs directory and the name of next make log file
TIMESTAMP=$(date +%s)
BUILD_LOG_PATH=${CUR_DIR}/logs
if [ ! -d ${BUILD_LOG_PATH} ]; then
    mkdir ${BUILD_LOG_PATH}
fi
MAKE_LOG_FILE=${BUILD_LOG_PATH}/remake.log
echo -e "Enter \033[34m${BUILD_PATH}\033[0m.."

cd ${BUILD_PATH}
echo -e "Running make..(See \033[34m${MAKE_LOG_FILE}\033[0m for detail)"
make -j >${MAKE_LOG_FILE} 2>&1 && echo -e "\033[32m Rebuild successfully! \033[0m" || (echo -e "\033[31m Rebuild fail! \033[0m"; exit -1)

echo -e "Leave \033[34m${BUILD_PATH}\033[0m.."
# leave BUILD_PATH
cd ${CUR_DIR}
RUN_DIRECTORY_64=${BUILD_PATH}/bin64
RUN_DIRECTORY_32=${BUILD_PATH}/bin32
RUN_DIRECTORY=${RUN_DIRECTORY_32}
if [ ! -d ${RUN_DIRECTORY_64} ]; then
    RUN_DIRECTORY=${RUN_DIRECTORY_32}
else
    RUN_DIRECTORY=${RUN_DIRECTORY_64}
fi

APPSAMPLES=${CUR_DIR}/appsamples
APPSAMPLES_SRC=${APPSAMPLES}/src
APPSAMPLES_BUILD=${APPSAMPLES}/build

APP1_SRC=${APPSAMPLES_SRC}/sample/sample_cct.cxx
APP2_SRC=${APPSAMPLES_SRC}/sample/sample_multithread.cxx
APP3_SRC=${APPSAMPLES_SRC}/sample/sample_reuse.cxx

APP1=sample_cct
APP2=sample_multithread
APP3=sample_reuse

APP1_FULL_PATH=${APPSAMPLES_BUILD}/sample_cct
APP2_FULL_PATH=${APPSAMPLES_BUILD}/sample_multithread
APP3_FULL_PATH=${APPSAMPLES_BUILD}/sample_reuse

echo -e "Enter \033[34m${APPSAMPLES}\033[0m.."
cd ${APPSAMPLES}
echo -e "\033[32mStart build app... \033[0m"
# build sample1
g++ -g ${APP1_SRC} -o ${APP1_FULL_PATH}
g++ -g ${APP2_SRC} -o ${APP2_FULL_PATH} -pthread
g++ -g ${APP3_SRC} -o ${APP3_FULL_PATH}
echo -e "\033[32m Build app successfully! \033[0m"
echo -e "Leave \033[34m${APPSAMPLES}\033[0m.."