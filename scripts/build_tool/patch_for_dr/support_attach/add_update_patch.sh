#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

function replace_and_backup_file {
    r_b_file=$1/$2
    echo "replace and back up ${r_b_file}"
    if [ ! -f ${r_b_file}.back ]; then
        if [ -f ${r_b_file} ]; then
            cp ${r_b_file} ${r_b_file}.back
        fi
    fi
    if [ -f ${r_b_file} ]; then
        rm -rf ${r_b_file}
    else
        echo -e "\033[34m Warn: ${r_b_file} is missing.\033[0m"
    fi
    cp ${2} ${1}
}

function replace_file {
    r_b_file=$1/$2
    echo "replace ${r_b_file}"
    if [ -f ${r_b_file} ]; then
        rm -rf ${r_b_file}
    fi
    cp ${2} ${1}
}


CUR_DIR=$(cd "$(dirname "$0")";pwd)
PATCH_DR_CORE_PATH=dr_root/core
PATCH_DR_CORE_LIB_PATH=dr_root/core/lib
PATCH_DR_CORE_UNIX_PATH=dr_root/core/unix
PATCH_DR_TOOLS_PATH=dr_root/tools

DR_ROOT_PATH=$(cd "$CUR_DIR/../../../../dynamorio";pwd)
DR_CORE_PATH=$DR_ROOT_PATH/core
DR_CORE_LIB_PATH=$DR_ROOT_PATH/core/lib
DR_CORE_UNIX_PATH=$DR_ROOT_PATH/core/unix
DR_TOOLS_PATH=$DR_ROOT_PATH/tools

cd $CUR_DIR
cd $PATCH_DR_CORE_PATH
replace_and_backup_file $DR_CORE_PATH dynamo.c
replace_and_backup_file $DR_CORE_PATH dispatch.c
replace_and_backup_file $DR_CORE_PATH globals.h
replace_and_backup_file $DR_CORE_PATH heap.c
replace_and_backup_file $DR_CORE_PATH synch.c
replace_and_backup_file $DR_CORE_PATH CMakeLists.txt

cd unix
replace_file $DR_CORE_UNIX_PATH drcct_attach.c
replace_and_backup_file $DR_CORE_UNIX_PATH loader.c
replace_and_backup_file $DR_CORE_UNIX_PATH signal.c

cd ../lib
replace_and_backup_file $DR_CORE_LIB_PATH dr_app.h
replace_file $DR_CORE_LIB_PATH drcct_attach.h

cd ../../tools
replace_file $DR_TOOLS_PATH drcctprof.c
replace_and_backup_file $DR_TOOLS_PATH CMakeLists.txt