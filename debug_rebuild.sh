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
MAKE_LOG_FILE=${BUILD_LOG_PATH}/remake.log
echo -e "Enter \033[34m${BUILD_PATH}\033[0m.."

cd ${BUILD_PATH}
echo -e "Running make..(See \033[34m${MAKE_LOG_FILE}\033[0m for detail)"
make -j8 >${MAKE_LOG_FILE} 2>&1 && echo -e "\033[32m Rebuild successfully! \033[0m" || (echo -e "\033[31m Rebuild fail! \033[0m"; exit -1)

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
APP1_SRC=${APPSAMPLES_SRC}/sample/sample.cxx
APP2_SRC=${APPSAMPLES_SRC}/sample/sample_cct.cxx
APP3_SRC=${APPSAMPLES_SRC}/sample/sample_multithread.cxx
APP1=${APPSAMPLES_BUILD}/sample
APP2=${APPSAMPLES_BUILD}/sample_cct
APP3=${APPSAMPLES_BUILD}/sample_multithread

rm -rf ${APPSAMPLES_BUILD}
mkdir ${APPSAMPLES_BUILD}

echo -e "Enter \033[34m${APPSAMPLES}\033[0m.."
cd ${APPSAMPLES}
echo -e "\033[32mStart build app... \033[0m"
# build sample1
g++ -g ${APP1_SRC} -o ${APP1}
g++ -g ${APP2_SRC} -o ${APP2}
g++ -g ${APP3_SRC} -o ${APP3} -pthread
echo -e "\033[32m Build app successfully! \033[0m"
echo -e "Leave \033[34m${APPSAMPLES}\033[0m.."

cd ${BUILD_LOG_PATH}

for i in 4
do
NPROC=${i}
export OMP_NUM_THREADS=${NPROC}
echo $OMP_NUM_THREADS
export OMP_DYNAMIC=FALSE
echo "run ${APP1}"
(time ${APP1}) > sample.runtime.${TIMESTAMP} 2>&1
echo "run ${APP2}"
(time ${APP2}) > sample_cct.runtime.${TIMESTAMP} 2>&1
echo "run ${APP3}"
(time ${APP3}) > sample_multithread.runtime.${TIMESTAMP} 2>&1

echo "run drcctlib_test_client ${APP1}"
(time ${RUN_DIRECTORY}/drrun -t drcctlib_test_client -- ${APP1} > test_client.sample.log.${TIMESTAMP} 2>&1) > test_client.sample.runtime.${TIMESTAMP} 2>&1
echo "run drcctlib_test_client ${APP2}"
(time ${RUN_DIRECTORY}/drrun -t drcctlib_test_client -- ${APP2} > test_client.sample_cct.log.${TIMESTAMP} 2>&1) > test_client.sample_cct.runtime.${TIMESTAMP} 2>&1
echo "run drcctlib_test_client ${APP3}"
(time ${RUN_DIRECTORY}/drrun -t drcctlib_test_client -- ${APP3} > test_client.sample_multithread.log.${TIMESTAMP} 2>&1) > test_client.sample_multithread.runtime.${TIMESTAMP} 2>&1

echo "run drcctlib_client ${APP1}"
(time ${RUN_DIRECTORY}/drrun -t drcctlib_client -- ${APP1} > client.sample.log.${TIMESTAMP} 2>&1) > client.sample.runtime.${TIMESTAMP} 2>&1
echo "run drcctlib_client ${APP2}"
(time ${RUN_DIRECTORY}/drrun -t drcctlib_client -- ${APP2} > client.sample_cct.log.${TIMESTAMP} 2>&1) > client.sample_cct.runtime.${TIMESTAMP} 2>&1
echo "run drcctlib_client ${APP3}"
(time ${RUN_DIRECTORY}/drrun -t drcctlib_client -- ${APP3} > client.sample_multithread.log.${TIMESTAMP} 2>&1) > client.sample_multithread.runtime.${TIMESTAMP} 2>&1

done

