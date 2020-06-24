#! /bin/bash

# set -euo pipefail

CUR_DIR=$(cd "$(dirname "$0")";pwd)

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

INPUT=10
# INPUT=5

cd ${BUILD_LOG_PATH}
export OMP_NUM_THREADS=1
# export OMP_DYNAMIC=FALSE
# export KMP_SCHEDULE=static,balanced
export GOMP_CPU_AFFINITY="0-63"
time /home/ubuntu/DrCCTProf-ARM-samples/lulesh/build/lulesh-par-original $INPUT

# time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex  -loglevel 4 -t drcctlib_all_instr_cct -- /home/ubuntu/DrCCTProf-ARM-samples/lulesh/build/lulesh-par-original $INPUT

# time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t dr_overhead_test -- /home/ubuntu/DrCCTProf-ARM-samples/lulesh/build/lulesh-par-original $INPUT

# time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_all_instr_cct_no_cache -- /home/ubuntu/DrCCTProf-ARM-samples/lulesh/build/lulesh-par-original $INPUT

time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_all_instr_cct -- /home/ubuntu/DrCCTProf-ARM-samples/lulesh/build/lulesh-par-original $INPUT

# time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_cct_only_op -- /home/ubuntu/DrCCTProf-ARM-samples/lulesh/build/lulesh-par-original $INPUT

# time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_memory_only_op -- /home/ubuntu/DrCCTProf-ARM-samples/lulesh/build/lulesh-par-original $INPUT

# time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_memory_with_data_centric_op -- /home/ubuntu/DrCCTProf-ARM-samples/lulesh/build/lulesh-par-original $INPUT

# time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_memory_with_data_centric_with_search_op -- /home/ubuntu/DrCCTProf-ARM-samples/lulesh/build/lulesh-par-original $INPUT

# time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_instr_statistics -- /home/ubuntu/DrCCTProf-ARM-samples/lulesh/build/lulesh-par-original $INPUT

# time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_reuse_distance_client_cache -- /home/ubuntu/DrCCTProf-ARM-samples/lulesh/build/lulesh-par-original $INPUT

# time ${RUN_DIRECTORY}/drrun -unsafe_build_ldstex -t drcctlib_reuse_distance -- /home/ubuntu/DrCCTProf-ARM-samples/lulesh/build/lulesh-par-original $INPUT