cd /home/dolanwm/app/lulesh1.0

main=lulesh-par-original
compiler=g++
g++ -g -O3 -fopenmp luleshOMP-0611.cc instrument.cc -DPOLYBENCH_TIME -o ${main}

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

# cd ${BUILD_LOG_PATH}
# ${RUN_DIRECTORY}/drrun -max_bb_instrs 128 -max_trace_bbs 16 -t drcctlib_client -- /home/dolanwm/app/LULESH/build/lulesh2.0 > ${DR_LOG_FILE} 2>&1
echo "run lulesh1.0"
time /home/dolanwm/app/lulesh1.0/${main}
done