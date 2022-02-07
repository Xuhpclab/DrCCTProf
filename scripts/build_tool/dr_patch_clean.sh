#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2022 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

# PLATFORM=$(uname -m)
# IS_X86=false
# if [ $PLATFORM == 'x86_64' ]; then
#     IS_X86=true
# fi

# if [ "$IS_X86" == "true" ]; then
#     # necessary patch for dynamorio
#     $CUR_DIR/patch_for_dr/clean_patch.sh
# fi

$CUR_DIR/patch_for_dr/support_c++17/clean_patch.sh >> /dev/null 2>&1