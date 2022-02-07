#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2022 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

CUR_DIR=$(cd "$(dirname "$0")";pwd)

for i in "$@"; do
  case $i in
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

BUILD_PATH=$CUR_DIR/../../build
if [ "$DEBUG" == "true" ]; then
    BUILD_PATH=$CUR_DIR/../../build_debug
fi
echo -e "Remove \033[34m$BUILD_PATH\033[0m .."
if [ -d $BUILD_PATH ]; then
    rm -rf $BUILD_PATH
fi


