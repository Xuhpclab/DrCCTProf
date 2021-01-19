#! /bin/bash

# **********************************************************
# Copyright (c) 2020 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

DYNAMORIO_ROOT_PATH=$CUR_DIR/../../../dynamorio

cd $DYNAMORIO_ROOT_PATH
CUR_DR_VERSION=$(git rev-parse HEAD)

if [ $CUR_DR_VERSION == 'f5016906b5699773acf52dd7f5147da89f10ae12' ]; then
    $CUR_DIR/support_attach/clean_patch.sh
fi