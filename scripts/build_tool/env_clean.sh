#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

DYNAMORIO_EXT_PATH=$CUR_DIR/../../dynamorio/ext
echo -e "Remove \033[34m$DYNAMORIO_EXT_PATH/drcctlib\033[0m.."
rm -rf $DYNAMORIO_EXT_PATH/drcctlib

if [ -f $DYNAMORIO_EXT_PATH/CMakeLists.txt ]; then
    if [ -f $DYNAMORIO_EXT_PATH/CMakeLists.txt.back ]; then
        rm -rf $DYNAMORIO_EXT_PATH/CMakeLists.txt
        cp  $DYNAMORIO_EXT_PATH/CMakeLists.txt.back $DYNAMORIO_EXT_PATH/CMakeLists.txt
        rm -rf $DYNAMORIO_EXT_PATH/CMakeLists.txt.back
    fi
else
    echo -e "\033[34mWarn(env_clean): In \"dynamorio/ext\", CmakeList.txt is missing.\033[0m"
fi


DYNAMORIO_CLIENT_PATH=$CUR_DIR/../../dynamorio/clients
echo -e "Remove \033[34m$DYNAMORIO_CLIENT_PATH/drcctlib*\033[0m.."
rm -rf $DYNAMORIO_CLIENT_PATH/drcctlib*
rm -rf $DYNAMORIO_CLIENT_PATH/drcctprof*

# PLATFORM=$(uname -m)
# IS_X86=false
# if [ $PLATFORM == 'x86_64' ]; then
#     IS_X86=true
# fi

# if [ "$IS_X86" == "true" ]; then
#     # necessary patch for dynamorio
#     $CUR_DIR/patch_for_dr/clean_patch.sh
# fi