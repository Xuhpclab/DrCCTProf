#! /bin/bash

CUR_DIR=$(cd "$(dirname "$0")";pwd)

echo -e "init env..."
$CUR_DIR/scripts/env_init.sh

echo -e "make..."
$CUR_DIR/scripts/make.sh

echo -e "make test..."
$CUR_DIR/scripts/make_tests.sh
