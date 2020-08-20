#! /bin/bash

# **********************************************************
# Copyright (c) 2020 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

cmake_version_str=$(cmake --version | grep version)

cmake_version_str=${cmake_version_str#"cmake version"}
### get version code
MAJOR="${cmake_version_str%.*}"

echo $MAJOR