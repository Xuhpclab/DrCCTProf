#! /bin/bash

CUR_DIR=$(pwd)

BUILD_LOG_PATH=${CUR_DIR}/logs
echo -e "Remove \033[34m${BUILD_LOG_PATH}\033[0m.."
rm -rf ${BUILD_LOG_PATH}/arm*
rm -rf ${BUILD_LOG_PATH}/x86*
rm -rf ${BUILD_LOG_PATH}/client*
rm -rf ${BUILD_LOG_PATH}/test_client*
rm -rf ${BUILD_LOG_PATH}/lulesh*
rm -rf ${BUILD_LOG_PATH}/sample*