#! /bin/bash

# **********************************************************
# Copyright (c) 2020 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
# **********************************************************

### configure C compiler
export compiler=$(which gcc)
 
### get version code
MAJOR=$(echo __GNUC__ | $compiler -E -xc - | tail -n 1)
MINOR=$(echo __GNUC_MINOR__ | $compiler -E -xc - | tail -n 1)
PATCHLEVEL=$(echo __GNUC_PATCHLEVEL__ | $compiler -E -xc - | tail -n 1)

echo $MAJOR