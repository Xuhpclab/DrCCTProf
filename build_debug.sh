#! /bin/bash

CUR_DIR=$(cd "$(dirname "$0")";pwd)

echo -e "init env..."
$CUR_DIR/scripts/build_tool/env_init.sh

echo -e "make -DEBUG..."
$CUR_DIR/scripts/build_tool/make.sh -DEBUG

echo -e "make test -DEBUG..."
$CUR_DIR/scripts/build_tool/make_tests.sh -DEBUG
