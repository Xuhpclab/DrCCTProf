#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

DYNAMORIO_ROOT_PATH=$CUR_DIR/../../../../dynamorio

cd $DYNAMORIO_ROOT_PATH
# CUR_DR_VERSION=$(git rev-parse HEAD)
# echo "CUR_DR_VERSION=$CUR_DR_VERSION"
git apply -R $CUR_DIR/dr-c++17-patch.diff