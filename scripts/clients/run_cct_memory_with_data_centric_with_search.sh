#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd) 

APP_FULL_PATH=$1
APP_ARG1=$2
APP_ARG2=$3
APP_ARG3=$4
APP_ARG4=$5
APP_ARG5=$6
APP_ARG6=$7
APP_ARG7=$8
APP_ARG8=$9

$CUR_DIR/run_client.sh drcctlib_memory_with_data_centric_with_search $APP_FULL_PATH $APP_ARG1 $APP_ARG2 $APP_ARG3 $APP_ARG4 $APP_ARG5 $APP_ARG6 $APP_ARG7 $APP_ARG8