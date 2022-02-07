#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2022 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

for i in "$@"; do
  case $i in
    --build_cpp_version=*)
      BUILD_CPP_VERSION="${i#*=}"
      shift # past argument=value
      ;;
    --debug=*)
      DEBUG="${i#*=}"
      shift # past argument=value
      ;;
    -*|--*)
      echo "Unknown option $i"
      exit 1
      ;;
    *)
      ;;
  esac
done


CUR_DIR=$(cd "$(dirname "$0")";pwd)

echo -e "add dynamorio patch..."
$CUR_DIR/scripts/build_tool/dr_patch_add.sh --build_cpp_version=${BUILD_CPP_VERSION}

echo -e "init env..."
$CUR_DIR/scripts/build_tool/env_init.sh

echo -e "make..."
$CUR_DIR/scripts/build_tool/make.sh --debug=${DEBUG}

echo -e "make test..."
$CUR_DIR/scripts/build_tool/make_tests.sh --debug=${DEBUG}
