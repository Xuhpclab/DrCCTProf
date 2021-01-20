#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

BUILD_LOG_PATH=$CUR_DIR/../logs
echo -e "Remove \033[34m$BUILD_LOG_PATH\033[0m .."
rm -rf $BUILD_LOG_PATH/*
