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
# make -j >${MAKE_LOG_FILE} 2>&1 && echo -e "\033[32m Rebuild successfully! \033[0m" || (echo -e "\033[31m Rebuild fail! \033[0m"; exit -1)

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

# rm -rf ${APPSAMPLES_BUILD}
# mkdir ${APPSAMPLES_BUILD}

echo -e "Enter \033[34m${APPSAMPLES}\033[0m.."
cd ${APPSAMPLES}
echo -e "\033[32mStart build app... \033[0m"
# build sample1
g++ -g ${APP1_SRC} -o ${APP1_FULL_PATH}
g++ -g ${APP2_SRC} -o ${APP2_FULL_PATH} -pthread
g++ -g ${APP3_SRC} -o ${APP3_FULL_PATH}
echo -e "\033[32m Build app successfully! \033[0m"
echo -e "Leave \033[34m${APPSAMPLES}\033[0m.."

for i in 1
do
cd ${BUILD_LOG_PATH}

echo "run ${APP1_FULL_PATH}"
(time ${APP1_FULL_PATH}) > runtime.${APP1}.${TIMESTAMP} 2>&1
echo "run ${APP2_FULL_PATH}"
(time ${APP2_FULL_PATH}) > runtime.${APP2}.${TIMESTAMP} 2>&1
echo "run ${APP3_FULL_PATH}"
(time ${APP3_FULL_PATH}) > runtime.${APP3}.${TIMESTAMP} 2>&1

echo "run drcctlib_all_instr_cct ${APP1_FULL_PATH}"
(time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_all_instr_cct -- ${APP1_FULL_PATH} > client.drcctlib_all_instr_cct.${APP1}.log.${TIMESTAMP} 2>&1) > runtime.drcctlib_all_instr_cct.${APP1}.${TIMESTAMP} 2>&1
echo "run drcctlib_all_instr_cct ${APP2_FULL_PATH}"
(time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_all_instr_cct -- ${APP2_FULL_PATH} > client.drcctlib_all_instr_cct.${APP2}.log.${TIMESTAMP} 2>&1) > runtime.drcctlib_all_instr_cct.${APP2}.${TIMESTAMP} 2>&1

echo "run drcctlib_instr_statistics ${APP1_FULL_PATH}"
(time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_instr_statistics -- ${APP1_FULL_PATH} > client.drcctlib_instr_statistics.${APP1}.log.${TIMESTAMP} 2>&1) > runtime.drcctlib_instr_statistics.${APP1}.${TIMESTAMP} 2>&1
echo "run drcctlib_instr_statistics ${APP2_FULL_PATH}"
(time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_instr_statistics -- ${APP2_FULL_PATH} > client.drcctlib_instr_statistics.${APP2}.log.${TIMESTAMP} 2>&1) > runtime.drcctlib_instr_statistics.${APP2}.${TIMESTAMP} 2>&1

echo "run drcctlib_reuse_distance ${APP3_FULL_PATH}"
(time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_reuse_distance -- ${APP3_FULL_PATH} > client.drcctlib_reuse_distance.${APP3}.log 2>&1) > runtime.drcctlib_reuse_distance.${APP3} 2>&1

cd ${BUILD_LOG_PATH}
echo "run drcctlib_all_instr_cct_hpc_fmt ${APP2_FULL_PATH}"
(time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_all_instr_cct_hpc_fmt -- ${APP2_FULL_PATH} > client.drcctlib_all_instr_cct_hpc_fmt.${APP2}.log 2>&1) > runtime.drcctlib_all_instr_cct_hpc_fmt.${APP2} 2>&1
cd ${CUR_DIR}
${CUR_DIR}/machine_custom_hpc_fmt.sh $APP2 $APP2_FULL_PATH $APPSAMPLES_SRC ${BUILD_LOG_PATH}

cd ${BUILD_LOG_PATH}
echo "run drcctlib_reuse_distance_hpc_fmt ${APP3_FULL_PATH}"
(time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_reuse_distance_hpc_fmt -- ${APP3_FULL_PATH} > client.drcctlib_reuse_distance_hpc_fmt.${APP3}.log 2>&1) > runtime.drcctlib_reuse_distance_hpc_fmt.${APP3} 2>&1
cd ${CUR_DIR}
${CUR_DIR}/machine_custom_hpc_fmt.sh $APP3 $APP3_FULL_PATH $APPSAMPLES_SRC ${BUILD_LOG_PATH}


done