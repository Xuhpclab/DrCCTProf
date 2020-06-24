#! /bin/bash

cmd_print_to_log () {
    echo "  " >> $2
    echo "### CMD: $1" >> $2
    echo "  " >> $2
    echo "\`\`\`" >> $2
    $1 >> $2 2>&1
    echo "\`\`\`" >> $2
}

rm -r debug_log
mkdir debug_log

echo "# server config" > debug_log/server_conf.md
LOG_FILE=debug_log/server_conf.md
# cpu cache memory info
cmd_print_to_log "lscpu" $LOG_FILE
cmd_print_to_log "cat /proc/cpuinfo" $LOG_FILE
cmd_print_to_log "cat /proc/meminfo" $LOG_FILE
# os info
cmd_print_to_log "lsb_release -a" $LOG_FILE
cmd_print_to_log "cat /proc/version" $LOG_FILE
cmd_print_to_log "uname -a" $LOG_FILE
cmd_print_to_log "cat /proc/modules" $LOG_FILE
# software info
cmd_print_to_log "env" $LOG_FILE
cmd_print_to_log "cmake --version" $LOG_FILE
cmd_print_to_log "gcc --version" $LOG_FILE
cmd_print_to_log "g++ --version" $LOG_FILE
cmd_print_to_log "locate libpthread.so" $LOG_FILE
cmd_print_to_log "ldd /bin/ls" $LOG_FILE
cmd_print_to_log "ldd appsamples/build/sample_multithread" $LOG_FILE

mkdir debug_log/cct_logs
mkdir debug_log/dr_logs
tar -jcvf cct_logs.tar.bz2 logs
tar -jcvf dr_logs.tar.bz2 build_debug/logs/
mv cct_logs.tar.bz2 debug_log/cct_logs/
mv dr_logs.tar.bz2 debug_log/dr_logs/
tar -jcvf debug_log.tar.bz2 debug_log
rm -r debug_log