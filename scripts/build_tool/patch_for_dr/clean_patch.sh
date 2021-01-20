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
        $CUR_DIR/support_attach/clean_patch.sh
    else
        git reset --hard f5016906b5699773acf52dd7f5147da89f10ae12
        git clean -df
    fi
fi
