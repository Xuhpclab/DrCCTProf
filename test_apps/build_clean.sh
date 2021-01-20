#! /bin/bash

# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

set -euo pipefail

CUR_DIR=$(cd "$(dirname "$0")";pwd)
BUILD=${CUR_DIR}/build
echo -e "Remove \033[34m${BUILD}\033[0m.."
rm -rf ${BUILD}