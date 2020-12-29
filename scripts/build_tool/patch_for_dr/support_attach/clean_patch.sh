#! /bin/bash

# **********************************************************
# Copyright (c) 2020 Xuhpclab. All rights reserved.
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
        rm -rf ${1}
    fi
}


CUR_DIR=$(cd "$(dirname "$0")";pwd)

DYNAMORIO_ROOT_PATH=$(cd "$CUR_DIR/../../../../dynamorio";pwd)
DYNAMORIO_CORE_PATH=$DYNAMORIO_ROOT_PATH/core
DYNAMORIO_CORE_LIB_PATH=$DYNAMORIO_ROOT_PATH/core/lib
DYNAMORIO_CORE_UNIX_PATH=$DYNAMORIO_ROOT_PATH/core/unix
DYNAMORIO_TOOLS_PATH=$DYNAMORIO_ROOT_PATH/tools

replace_with_backup_file $DYNAMORIO_CORE_PATH/dynamo.c
replace_with_backup_file $DYNAMORIO_CORE_PATH/dispatch.c
replace_with_backup_file $DYNAMORIO_CORE_PATH/globals.h
replace_with_backup_file $DYNAMORIO_CORE_PATH/heap.c
replace_with_backup_file $DYNAMORIO_CORE_PATH/synch.c
replace_with_backup_file $DYNAMORIO_CORE_PATH/CMakeLists.txt


remove_file $DYNAMORIO_CORE_UNIX_PATH/drcctprof_attach.c
replace_with_backup_file $DYNAMORIO_CORE_UNIX_PATH/loader.c
replace_with_backup_file $DYNAMORIO_CORE_UNIX_PATH/signal.c

replace_with_backup_file $DYNAMORIO_CORE_LIB_PATH/dr_app.h
remove_file $DYNAMORIO_CORE_LIB_PATH/drcctprof_attach.h
remove_file $DYNAMORIO_TOOLS_PATH/drcctprofattach.c
replace_with_backup_file $DYNAMORIO_TOOLS_PATH/CMakeLists.txt

# replace_with_backup_file $DYNAMORIO_CORE_LIB_PATH/dr_inject.h
# replace_with_backup_file $DYNAMORIO_CORE_UNIX_PATH/injector.c
# replace_with_backup_file $DYNAMORIO_TOOLS_PATH/drdeploy.c