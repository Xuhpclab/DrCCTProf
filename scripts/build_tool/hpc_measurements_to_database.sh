#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

HPCPROFTT=$1
HPCSTRUCT=$2
HPCSTPROF=$3
APP_NAME=$4
BIN_DIR=$5
SRC_DIR=$6
LOG_DIR=$7

cd $LOG_DIR
HPCTOOLKIT_MEASUREMENTS_DIR=$LOG_DIR/hpctoolkit-$APP_NAME-measurements
HPCTOOLKIT_MEASUREMENTS_HPCRUNS=$(ls $HPCTOOLKIT_MEASUREMENTS_DIR)
for HPCRUN in $HPCTOOLKIT_MEASUREMENTS_HPCRUNS
do
    echo "$HPCPROFTT $HPCTOOLKIT_MEASUREMENTS_DIR/$HPCRUN > $LOG_DIR/$HPCRUN.tt.log" && $HPCPROFTT $HPCTOOLKIT_MEASUREMENTS_DIR/$HPCRUN > $LOG_DIR/$HPCRUN.tt.log && echo -e "\033[32m----------PASSED---------\033[0m" || (echo -e "\033[31m----------FAILED---------\033[0m"; exit -1)
done

echo "$HPCSTRUCT $BIN_DIR"
$HPCSTRUCT $BIN_DIR

echo "$HPCSTPROF -S $APP_NAME.hpcstruct -I $SRC_DIR $HPCTOOLKIT_MEASUREMENTS_DIR"
$HPCSTPROF -S $APP_NAME.hpcstruct -I $SRC_DIR $HPCTOOLKIT_MEASUREMENTS_DIR

HPCTOOLKIT_DATABASE_DIR_NAME=hpctoolkit-$APP_NAME-database
tar -jcvf $HPCTOOLKIT_DATABASE_DIR_NAME.tar.bz2 $HPCTOOLKIT_DATABASE_DIR_NAME

