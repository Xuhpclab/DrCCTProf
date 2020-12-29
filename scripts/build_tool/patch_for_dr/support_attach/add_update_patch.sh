#! /bin/bash

# **********************************************************
# Copyright (c) 2020 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

function replace_and_backup_file {
    echo "replace and back up $1"
    if [ ! -f ${1}.back ]; then
        if [ -f ${1} ]; then
            cp ${1} ${1}.back
        fi
    fi
    if [ -f ${1} ]; then
        rm -rf ${1}
    else
        echo -e "\033[34m Warn: ${1} is missing.\033[0m"
    fi
    cp  ${2} ${1}
}

function replace_file {
    echo "replace $1"
    if [ -f ${1} ]; then
        rm -rf ${1}
    fi
    cp  ${2} ${1}
}


CUR_DIR=$(cd "$(dirname "$0")";pwd)

DYNAMORIO_ROOT_PATH=$(cd "$CUR_DIR/../../../../dynamorio";pwd)
DYNAMORIO_CORE_PATH=$DYNAMORIO_ROOT_PATH/core
DYNAMORIO_CORE_LIB_PATH=$DYNAMORIO_ROOT_PATH/core/lib
DYNAMORIO_CORE_UNIX_PATH=$DYNAMORIO_ROOT_PATH/core/unix
DYNAMORIO_TOOLS_PATH=$DYNAMORIO_ROOT_PATH/tools

replace_and_backup_file $DYNAMORIO_CORE_PATH/dynamo.c $CUR_DIR/dynamo.c
replace_and_backup_file $DYNAMORIO_CORE_PATH/dispatch.c $CUR_DIR/dispatch.c
replace_and_backup_file $DYNAMORIO_CORE_PATH/globals.h $CUR_DIR/globals.h
replace_and_backup_file $DYNAMORIO_CORE_PATH/heap.c $CUR_DIR/heap.c
replace_and_backup_file $DYNAMORIO_CORE_PATH/synch.c $CUR_DIR/synch.c
replace_and_backup_file $DYNAMORIO_CORE_PATH/CMakeLists.txt $CUR_DIR/CMakeLists.txt.core

replace_file $DYNAMORIO_CORE_UNIX_PATH/drcctprof_attach.c $CUR_DIR/drcctprof_attach.c
replace_and_backup_file $DYNAMORIO_CORE_UNIX_PATH/loader.c $CUR_DIR/loader.c
replace_and_backup_file $DYNAMORIO_CORE_UNIX_PATH/signal.c $CUR_DIR/signal.c

replace_and_backup_file $DYNAMORIO_CORE_LIB_PATH/dr_app.h $CUR_DIR/dr_app.h
replace_file $DYNAMORIO_CORE_LIB_PATH/drcctprof_attach.h $CUR_DIR/drcctprof_attach.h
replace_file $DYNAMORIO_CORE_LIB_PATH/drcctprof_attach.h $CUR_DIR/drcctprof_attach.h

replace_file $DYNAMORIO_TOOLS_PATH/drcctprofattach.c $CUR_DIR/drcctprofattach.c
replace_and_backup_file $DYNAMORIO_TOOLS_PATH/CMakeLists.txt $CUR_DIR/CMakeLists.txt.tools

# replace_and_backup_file $DYNAMORIO_CORE_LIB_PATH/dr_inject.h $CUR_DIR/dr_inject.h
# replace_and_backup_file $DYNAMORIO_CORE_UNIX_PATH/injector.c $CUR_DIR/injector.c
# replace_and_backup_file $DYNAMORIO_TOOLS_PATH/drdeploy.c $CUR_DIR/drdeploy.c