#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2022 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

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
if [ "$DEBUG" == "true" ] ; then
    BUILD_PATH=$CUR_DIR/../../build_debug
fi
LOG_PATH=$CUR_DIR/../../logs

MAKE_LOG_FILE=$LOG_PATH/remake.log
if [ "$DEBUG" == "true" ] ; then
    MAKE_LOG_FILE=$LOG_PATH/remake_debug.log
fi

echo -e "Enter \033[34m$BUILD_PATH\033[0m .."
# enter BUILD_PATH
cd $BUILD_PATH

# start remake
echo -e "Running remake .. (See \033[34m$MAKE_LOG_FILE\033[0m for detail)"
make -j >$MAKE_LOG_FILE 2>&1 && echo -e "\033[32m Remake successfully! \033[0m" || (echo -e "\033[31m Remake fail! \033[0m"; exit -1)