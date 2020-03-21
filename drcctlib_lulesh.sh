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

echo -e "Build Lulesh1.0.."
LULESH_SOURCE_PATH=${CUR_DIR}/appsamples/src/lulesh1.0
LULESH=${LULESH_SOURCE_PATH}/lulesh-par-original
g++ -g -O3 -fopenmp ${LULESH_SOURCE_PATH}/luleshOMP-0611.cc ${LULESH_SOURCE_PATH}/instrument.cc -DPOLYBENCH_TIME -o ${LULESH}
echo -e "Success build Lulesh1.0.."

cd ${BUILD_LOG_PATH}

for i in 1
do
NPROC=${i}
export OMP_NUM_THREADS=${NPROC}
echo $OMP_NUM_THREADS
export OMP_DYNAMIC=FALSE
export KMP_SCHEDULE=static,balanced
export GOMP_CPU_AFFINITY="0-63"
echo "run lulesh1.0"
(time ${LULESH}) > runtime.lulesh.${TIMESTAMP} 2>&1
echo "run drcctlib_client lulesh1.0"
(time ${RUN_DIRECTORY}/drrun -t drcctlib_client -- ${LULESH} > client.drcctlib_client.lulesh.log.${TIMESTAMP} 2>&1) > runtime.drcctlib_client.lulesh.${TIMESTAMP} 2>&1
echo "run drcctlib_instr_statistics lulesh1.0"
(time ${RUN_DIRECTORY}/drrun -t drcctlib_instr_statistics -- ${LULESH} > client.drcctlib_instr_statistics.lulesh.log.${TIMESTAMP} 2>&1) > runtime.drcctlib_instr_statistics.lulesh.${TIMESTAMP} 2>&1
done