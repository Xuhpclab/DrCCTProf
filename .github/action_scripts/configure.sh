#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

SRC_PATH=${GITHUB_WORKSPACE}/src
DRCCTLIB_PATH=${SRC_PATH}/drcctlib
DRCCTLIB_CLIENTS_ROOT_PATH=${SRC_PATH}/clients
DRCCTLIB_CLIENTS_NAME_LIST=$(ls ${DRCCTLIB_CLIENTS_ROOT_PATH})

DYNAMORIO_ROOT_PATH=${GITHUB_WORKSPACE}/dynamorio
DYNAMORIO_EXT_PATH=${DYNAMORIO_ROOT_PATH}/ext
DYNAMORIO_CLIENT_PATH=${DYNAMORIO_ROOT_PATH}/clients

echo -e "Linking source files and cmakefiles.."
# link drcctlib src to dynamorio ext path
rm -rf ${DYNAMORIO_EXT_PATH}/drcctlib
ln -s ${DRCCTLIB_PATH} ${DYNAMORIO_EXT_PATH}/drcctlib

# link cmakelists to dynamorio ext path
rm -rf ${DYNAMORIO_EXT_PATH}/CMakeLists.txt
ln -s  ${SRC_PATH}/CMakeLists.txt   ${DYNAMORIO_EXT_PATH}/CMakeLists.txt

# link drcctlib test to dynamorio clients path
for CLIENT in ${DRCCTLIB_CLIENTS_NAME_LIST}
do
    rm -rf ${DYNAMORIO_CLIENT_PATH}/${CLIENT}
    ln -s ${DRCCTLIB_CLIENTS_ROOT_PATH}/${CLIENT} ${DYNAMORIO_CLIENT_PATH}/${CLIENT}
done