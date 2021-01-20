#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

function replace_with_backup_file {
    if [ -f ${1}.back ]; then
        echo "replace with back up $1"
        if [ -f ${1} ]; then
            rm -rf ${1}
        fi
        cp ${1}.back ${1}
        rm ${1}.back
    else
        echo -e "\033[34m Warn: ${1}.back is missing.\033[0m"
    fi
}

function remove_file {
    if [ -f ${1} ]; then
        echo "remove_file $1"
        rm -rf ${1}
    fi
}


CUR_DIR=$(cd "$(dirname "$0")";pwd)

DR_ROOT_PATH=$(cd "$CUR_DIR/../../../../dynamorio";pwd)
DR_CORE_PATH=$DR_ROOT_PATH/core
DR_CORE_LIB_PATH=$DR_ROOT_PATH/core/lib
DR_CORE_UNIX_PATH=$DR_ROOT_PATH/core/unix
DR_TOOLS_PATH=$DR_ROOT_PATH/tools

replace_with_backup_file $DR_CORE_PATH/dynamo.c
replace_with_backup_file $DR_CORE_PATH/dispatch.c
replace_with_backup_file $DR_CORE_PATH/globals.h
replace_with_backup_file $DR_CORE_PATH/heap.c
replace_with_backup_file $DR_CORE_PATH/synch.c
replace_with_backup_file $DR_CORE_PATH/CMakeLists.txt

remove_file $DR_CORE_UNIX_PATH/drcct_attach.c
replace_with_backup_file $DR_CORE_UNIX_PATH/loader.c
replace_with_backup_file $DR_CORE_UNIX_PATH/signal.c

replace_with_backup_file $DR_CORE_LIB_PATH/dr_app.h
remove_file $DR_CORE_LIB_PATH/drcct_attach.h

remove_file $DR_TOOLS_PATH/drcctprof.c
replace_with_backup_file $DR_TOOLS_PATH/CMakeLists.txt