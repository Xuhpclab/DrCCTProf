# **********************************************************
# Copyright (c) 2020 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
#  **********************************************************

cmake_minimum_required(VERSION 2.6)

include(../../make/policies.cmake NO_POLICY_SCOPE)

if (UNIX)
  add_compile_options(-std=c++11)
  if (DEBUG)
    add_compile_options(-g)
  endif (DEBUG)
endif (UNIX)

set(DynamoRIO_USE_LIBC OFF)

set(srcs
  splay_tree.cpp
  drcctlib.cpp
  drcctlib_hpcviewer_format.cpp
  # add more here
  )

# i#1491#2: VS generators fail if static lib has resources
set(srcs_static ${srcs})

if (WIN32)
  set(srcs ${srcs} ${PROJECT_SOURCE_DIR}/core/win32/resources.rc)
endif ()

#if (UNIX)
#  add_compile_options(-O3)
#endif (UNIX)

add_library(drcctlib SHARED ${srcs})
set(PREFERRED_BASE 0x79000000)
configure_extension(drcctlib OFF)
use_DynamoRIO_extension(drcctlib drcontainers)
use_DynamoRIO_extension(drcctlib drmgr)
use_DynamoRIO_extension(drcctlib drutil)
use_DynamoRIO_extension(drcctlib drsyms)
use_DynamoRIO_extension(drcctlib drwrap)
use_DynamoRIO_extension(drcctlib drreg)

include_directories("${PROJECT_SOURCE_DIR}/ext/drsyms/libelftc/include")

add_library(drcctlib_static STATIC ${srcs_static})
configure_extension(drcctlib_static ON)
use_DynamoRIO_extension(drcctlib_static drcontainers)
use_DynamoRIO_extension(drcctlib_static drmgr_static)
use_DynamoRIO_extension(drcctlib_static drutil_static)
use_DynamoRIO_extension(drcctlib_static drsyms_static)
use_DynamoRIO_extension(drcctlib_static drwrap_static)
use_DynamoRIO_extension(drcctlib_static drreg_static)

install_ext_header(drcctlib_global_share.h)
install_ext_header(drcctlib_filter_func_list.h)
install_ext_header(drcctlib.h)
install_ext_header(drcctlib_ext.h)
install_ext_header(drcctlib_hpcviewer_format.h)
install_ext_header(shadow_memory.h)
install_ext_header(memory_cache.h)