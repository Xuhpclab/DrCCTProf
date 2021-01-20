#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

cmd_print_to_log () {
    echo "  " >> $2
    echo "### CMD: $1" >> $2
    echo "  " >> $2
    echo "\`\`\`" >> $2
    $1 >> $2 2>&1
    echo "\`\`\`" >> $2
}

LOG_FILE=server_cfg.md
echo "# server config" > $LOG_FILE
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