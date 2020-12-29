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

if [ $CUR_DR_VERSION == 'b5e95ea4b1e5449075bff539a33bd3d08712c414' ]; then
    $CUR_DIR/support_attach/clean_patch.sh
fi