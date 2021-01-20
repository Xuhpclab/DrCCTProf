#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)
DYNAMORIO_ROOT_PATH=$CUR_DIR/../../../../dynamorio

$CUR_DIR/add_update_patch.sh
cp $CUR_DIR/dr_root/.gitignore $DYNAMORIO_ROOT_PATH

cd $DYNAMORIO_ROOT_PATH
git add -A
git restore --staged .gitignore
git commit -m "attach patch"
git format-patch HEAD^
cp $DYNAMORIO_ROOT_PATH/0001-attach-patch.patch $CUR_DIR/drcct-attach-patch.patch
git reset --hard f5016906b5699773acf52dd7f5147da89f10ae12
git clean -df
git clean -df