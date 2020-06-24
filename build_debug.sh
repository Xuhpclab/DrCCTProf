#! /bin/bash

CUR_DIR=$(cd "$(dirname "$0")";pwd)

echo -e "init env..."
$CUR_DIR/scripts/env_init.sh

echo -e "make -DEBUG..."
$CUR_DIR/scripts/make.sh -DEBUG

echo -e "make test -DEBUG..."
$CUR_DIR/scripts/make_tests.sh -DEBUG
