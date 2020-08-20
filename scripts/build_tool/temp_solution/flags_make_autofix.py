#! /usr/bin/python3

# **********************************************************
# Copyright (c) 2020 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

import sys

filePath = sys.argv[1]

with open(filePath, "r+") as f:
    read_data = f.read()
    f.write(read_data.replace('--defsym ', '-D'))