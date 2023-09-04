#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

for i in "$@"; do
  case $i in
    --build_cpp_version=*)
      BUILD_CPP_VERSION="${i#*=}"
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

# PLATFORM=$(uname -m)
# IS_X86=false
# if [ $PLATFORM == 'x86_64' ]; then
#     IS_X86=true
# fi

# if [ "$IS_X86" == "true" ]; then
    # # necessary patch for dynamorio
    # $CUR_DIR/patch_for_dr/add_update_patch.sh
# fi

if [ "$BUILD_CPP_VERSION" == "c++17" ]; then
    # necessary patch for dynamorio
    $CUR_DIR/patch_for_dr/support_c++17/add_patch.sh
fi