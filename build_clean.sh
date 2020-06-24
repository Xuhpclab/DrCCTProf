#! /bin/bash

CUR_DIR=$(cd "$(dirname "$0")";pwd)

echo -e "clean logs..."
$CUR_DIR/scripts/build_tool/clean_logs.sh

echo -e "make clean..."
$CUR_DIR/scripts/build_tool/make_clean.sh

echo -e "make debug clean..."
$CUR_DIR/scripts/build_tool/make_clean.sh -DEBUG

echo -e "clean env config..."
$CUR_DIR/scripts/build_tool/env_clean.sh


