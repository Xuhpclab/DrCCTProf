#! /bin/bash

CUR_DIR=$(pwd)
TIMESTAMP=$(date +%s)
BUILD_LOG_PATH=${CUR_DIR}/logs
PIN_LOG_FILE=${BUILD_LOG_PATH}/pin.lulesh.${TIMESTAMP}.log
PIN_DIRECTORY=/home/dolanwm/Github/cctlib/pin-3.7-97619-g0d0c92f4f-gcc-linux
PIN_TOOL_DIRECTORY=/home/dolanwm/Github/cctlib/tests/obj-intel64
LULESH_PATH=/home/dolanwm/app/lulesh1.0

for i in $1
do
nproc=${i}
export OMP_NUM_THREADS=${nproc}
echo $OMP_NUM_THREADS
export OMP_DYNAMIC=FALSE
export KMP_SCHEDULE=static,balanced

#export KMP_AFFINITY="proclist=[0]"
#export KMP_AFFINITY="proclist=[0,1]"
#export KMP_AFFINITY="proclist=[0,1,2,3]"
#export KMP_AFFINITY="proclist=[0,1,2,3,4,5,6,7]"
#export KMP_AFFINITY="proclist=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]"
#export KMP_AFFINITY="proclist=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31]"

#export GOMP_CPU_AFFINITY="3"
#export GOMP_CPU_AFFINITY="0-1"
#export GOMP_CPU_AFFINITY="0-3"
#export GOMP_CPU_AFFINITY="0-7"
#export GOMP_CPU_AFFINITY="0-15"
export GOMP_CPU_AFFINITY="0-63"

#export LD_LIBRARY_PATH=/home/xl10/gperftools-2.0/install/lib:$LD_LIBRARY_PATH
#export LD_LIBRARY_PATH=/home/xl10/support/jemalloc-3.3.1/install/lib:$LD_LIBRARY_PATH
#export OMP_WAIT_POLICY=PASSIVE
#export OMP_WAIT_POLICY=ACTIVE
#export MALLOC_CONF="lg_dirty_mult:32"

# time ~/red-pebs/install/bin/hpcrun -e MEM_UOPS_RETIRED:ALL_STORES@500000 ./${main}
# done

cd ${BUILD_LOG_PATH}
echo "-----Test lulesh1.0-----(See${PIN_LOG_FILE} for detail)"
nohup time ${PIN_DIRECTORY}/pin -t ${PIN_TOOL_DIRECTORY}/cct_client.so -- ${LULESH_PATH}/lulesh-par-original > ${PIN_LOG_FILE} 2>&1 &
done
