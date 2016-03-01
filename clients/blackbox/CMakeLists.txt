# **********************************************************
# Copyright (c) 2016 UCI PLRG. All rights reserved.
# **********************************************************

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of VMware, Inc. nor the names of its contributors may be
#   used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

cmake_minimum_required(VERSION 2.6)

if (SECURITY_AUDIT) # around whole file

  add_definitions(-DJITOPT_NARROW_VMAREAS)

  # add blackbox client
  if (STATIC_LIBRARY)
    set(libtype STATIC)
  else()
    set(libtype SHARED)
  endif ()

  add_library(blackbox ${libtype}
    blackbox.c
    crowd_safe_util.c
    basic_block_hashtable.c
    basic_block_observer.c
    indirect_link_hashtable.c
    indirect_link_observer.c
    crowd_safe_gencode.c
    crowd_safe_trace.c
    link_observer.c
    module_observer.c
    network_monitor.c
    image_execution_monitor.c
    anonymous_execution_monitor.c
    blacklist.c
    # ? ../common/modules.c
    # add more here
    )
  configure_DynamoRIO_client(blackbox)
  use_DynamoRIO_extension(blackbox drcontainers)
  use_DynamoRIO_extension(blackbox drsyms)

  # ensure we rebuild if includes change
  add_dependencies(blackbox api_headers)

  # Provide a hint for how to use the client
  if (NOT DynamoRIO_INTERNAL OR NOT "${CMAKE_GENERATOR}" MATCHES "Ninja")
    add_custom_command(TARGET blackbox
      POST_BUILD
      COMMAND ${CMAKE_COMMAND}
      ARGS -E echo "Usage: pass to drconfig or drrun: -t blackbox"
      VERBATIM)
  endif ()

  if (WIN32 AND GENERATE_PDBS)
    # I believe it's the lack of CMAKE_BUILD_TYPE that's eliminating this?
    # In any case we make sure to add it (for release and debug, to get pdb):
    append_property_string(TARGET blackbox LINK_FLAGS "/debug")
  endif (WIN32 AND GENERATE_PDBS)

  DR_export_target(blackbox)
  install_exported_target(blackbox ${INSTALL_CLIENTS_LIB})

  DR_install(DIRECTORY "${DR_LIBRARY_OUTPUT_DIRECTORY}/"
    DESTINATION "${INSTALL_CLIENTS_BIN}"
    FILES_MATCHING
    PATTERN "dynamorio.dll" PATTERN "libdynamorio.so*"
    PATTERN "lib*.debug" EXCLUDE)
  if (NOT DR_EXT_DRSYMS_STATIC)
    DR_install(DIRECTORY
      "${DR_LIBRARY_OUTPUT_DIRECTORY}/../../ext/${INSTALL_LIB}/"
      DESTINATION "${INSTALL_CLIENTS_BIN}"
      FILES_MATCHING
      PATTERN "drsyms.dll" PATTERN "libdrsyms.so*"
      PATTERN "lib*.debug" EXCLUDE)
  endif (NOT DR_EXT_DRSYMS_STATIC)

  set(INSTALL_BLACKBOX_CONFIG ${INSTALL_CLIENTS_BASE})

  if (UNIX)
    set(LIB_EXT ".so")
    set(LIB_PFX "lib")
  else (UNIX)
    set(LIB_EXT ".dll")
    set(LIB_PFX "")
  endif (UNIX)

  #file(WRITE  ${CONFIG} "# blackbox tool config file\n")
  #file(APPEND ${CONFIG} "# DynamoRIO options\n")
  #file(APPEND ${CONFIG} "DR_OP=\n") # need this? -nop_initial_bblock\n")
  #file(APPEND ${CONFIG} "# client tool path\n")
  #file(APPEND ${CONFIG} "CLIENT_REL=${INSTALL_CLIENTS_LIB}/${LIB_PFX}blackbox${LIB_EXT}\n")
  #file(APPEND ${CONFIG} "# client tool options\n")
  #file(APPEND ${CONFIG} "TOOL_OP=\n")

  DR_install(FILES "${CONFIG}" DESTINATION ${INSTALL_BLACKBOX_CONFIG})

endif (SECURITY_AUDIT)
