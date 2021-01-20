#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

DEBUG_MODE=false
if [ "$1" == "-DEBUG" ] ; then
    DEBUG_MODE=true
fi


DYNAMORIO_ROOT_PATH=$CUR_DIR/../../../dynamorio

cd $DYNAMORIO_ROOT_PATH
CUR_DR_VERSION=$(git rev-parse HEAD)
echo "CUR_DR_VERSION=$CUR_DR_VERSION"

if [ $CUR_DR_VERSION == 'f5016906b5699773acf52dd7f5147da89f10ae12' ]; then
    if [ "$DEBUG_MODE" == "true" ] ; then
        echo "The current version of dynamorio supports adding support_attach patch."
        $CUR_DIR/support_attach/add_update_patch.sh
    else
        git am $CUR_DIR/support_attach/drcct-attach-patch.patch
        git reset --soft  HEAD^
    fi
else
    echo "Failed to add support_attach patch.The current version of Dynamorio does not support it.Please checkout the branch with last submitted as b5e95ea4b1e5449075bff539a33bd3d08712c414."
fi