# **********************************************************
# Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
# Licensed under the MIT License.
# See LICENSE file for more information.
#  **********************************************************

cmake_minimum_required(VERSION 3.7)

include(../../make/policies.cmake NO_POLICY_SCOPE)

if (UNIX)
  add_compile_options(-Wno-deprecated)
  add_compile_options(-Wno-unused-result)
  add_compile_options(-Wno-unused-variable)
  add_compile_options(-Wno-unused-local-typedefs)
  add_compile_options(-Wno-unused-function)
  add_compile_options(-Werror=sign-compare)
  add_compile_options(-Werror=narrowing)
  add_compile_options(-std=c++11)

  if (DEBUG)
    add_compile_options(-g3)
  endif (DEBUG)
endif (UNIX)

include_directories("${PROJECT_SOURCE_DIR}/ext/drsyms/libelftc/include")

# add third-party libraries

add_library(drcctlib_goroutines SHARED
drcctlib_goroutines.cpp
dr_go_wrap.cpp
cgo_funcs.cpp
elf_utils.cpp
  )

configure_DynamoRIO_client(drcctlib_goroutines)
use_DynamoRIO_extension(drcctlib_goroutines drcctlib)
place_shared_lib_in_lib_dir(drcctlib_goroutines)

add_dependencies(drcctlib_goroutines api_headers)

# Provide a hint for how to use the client
if (NOT DynamoRIO_INTERNAL OR NOT "${CMAKE_GENERATOR}" MATCHES "Ninja")
  add_custom_command(TARGET drcctlib_goroutines
    POST_BUILD
    COMMAND ${CMAKE_COMMAND}
    ARGS -E echo "Usage: pass to drconfig or drrun: -t drcctlib_goroutines"
    VERBATIM)
endif ()

install_target(drcctlib_goroutines ${INSTALL_CLIENTS_LIB})


set(INSTALL_DRCCTLIB_CLIENTS_LIB ${INSTALL_CLIENTS_BASE})

function (write_config_file dst bindir libdir)
  file(WRITE  ${dst} "# drcctlib_goroutines tool config file\n")
  file(APPEND ${dst} "CLIENT_REL=${libdir}/${LIB_PFX}drcctlib_goroutines${LIB_EXT}\n")
endfunction ()

if (X64)
  set(CONFIG_INSTALL ${PROJECT_BINARY_DIR}/drcctlib_goroutines.drrun64)
  set(CONFIG_BUILD ${PROJECT_BINARY_DIR}/tools/drcctlib_goroutines.drrun64)
else (X64)
  set(CONFIG_INSTALL ${PROJECT_BINARY_DIR}/drcctlib_goroutines.drrun32)
  set(CONFIG_BUILD ${PROJECT_BINARY_DIR}/tools/drcctlib_goroutines.drrun32)
endif (X64)

set(BUILD_CLIENTS_BIN clients/${INSTALL_BIN})
set(BUILD_CLIENTS_LIB clients/${INSTALL_LIB})

write_config_file(${CONFIG_INSTALL} ${INSTALL_CLIENTS_BIN} ${INSTALL_CLIENTS_LIB})
write_config_file(${CONFIG_BUILD} ${BUILD_CLIENTS_BIN} ${BUILD_CLIENTS_LIB})

DR_install(FILES "${CONFIG_INSTALL}" DESTINATION ${INSTALL_DRCCTLIB_CLIENTS_LIB})
register_tool_file("drcctlib_goroutines")

##################################################
# Documentation

