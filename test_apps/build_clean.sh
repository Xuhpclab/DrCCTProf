#! /bin/bash

set -euo pipefail

CUR_DIR=$(cd "$(dirname "$0")";pwd)
BUILD=${CUR_DIR}/build
echo -e "Remove \033[34m${BUILD}\033[0m.."
rm -rf ${BUILD}