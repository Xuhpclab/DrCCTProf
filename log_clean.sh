#! /bin/bash

CUR_DIR=$(pwd)

BUILD_LOG_PATH=${CUR_DIR}/logs
echo -e "Remove \033[34m${BUILD_LOG_PATH}\033[0m.."
rm -rf ${BUILD_LOG_PATH}/*
