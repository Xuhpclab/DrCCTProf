#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

SRC_PATH=$CUR_DIR/../../src
DRCCTLIB_PATH=$SRC_PATH/drcctlib
DRCCTLIB_CLIENTS_ROOT_PATH=$SRC_PATH/clients
DRCCTLIB_CLIENTS_NAME_LIST=$(ls $DRCCTLIB_CLIENTS_ROOT_PATH)

DYNAMORIO_ROOT_PATH=$CUR_DIR/../../dynamorio
DYNAMORIO_EXT_PATH=$DYNAMORIO_ROOT_PATH/ext
DYNAMORIO_CLIENT_PATH=$DYNAMORIO_ROOT_PATH/clients

echo -e "Linking source files and cmakefiles.."
# link drcctlib src to dynamorio ext path
rm -rf $DYNAMORIO_EXT_PATH/drcctlib
ln -s $DRCCTLIB_PATH $DYNAMORIO_EXT_PATH/drcctlib

# link cmakelists to dynamorio ext path
if [ ! -f $DYNAMORIO_EXT_PATH/CMakeLists.txt.back ]; then
    if [ -f $DYNAMORIO_EXT_PATH/CMakeLists.txt ]; then
        cp $DYNAMORIO_EXT_PATH/CMakeLists.txt $DYNAMORIO_EXT_PATH/CMakeLists.txt.back
    fi
fi
if [ -f $DYNAMORIO_EXT_PATH/CMakeLists.txt ]; then
    rm -rf $DYNAMORIO_EXT_PATH/CMakeLists.txt
else 
    echo -e "\033[34mWarn(env_clean): In \"dynamorio/ext\", CmakeList.txt is missing.\033[0m"
fi
ln -s  $SRC_PATH/CMakeLists.txt   $DYNAMORIO_EXT_PATH/CMakeLists.txt

# link drcctlib test to dynamorio clients path
for CLIENT in $DRCCTLIB_CLIENTS_NAME_LIST
do
    rm -rf $DYNAMORIO_CLIENT_PATH/$CLIENT
    ln -s $DRCCTLIB_CLIENTS_ROOT_PATH/$CLIENT $DYNAMORIO_CLIENT_PATH/$CLIENT
done

# PLATFORM=$(uname -m)
# IS_X86=false
# if [ $PLATFORM == 'x86_64' ]; then
#     IS_X86=true
# fi

# if [ "$IS_X86" == "true" ]; then
    # # necessary patch for dynamorio
    # $CUR_DIR/patch_for_dr/add_update_patch.sh
# fi
