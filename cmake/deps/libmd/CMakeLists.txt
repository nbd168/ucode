# Build wrapper for libmd (https://git.hadrons.org/git/libmd.git), which is
# autotools-only. Compiles the hash implementations directly; the
# autotools config.h is replaced by a minimal one (the sources only use
# HAVE_UNISTD_H).
#
# helper.c is an autotools template: it is compiled once per algorithm
# with hashinc -> <algo>.h and HASH -> <ALGO> substituted (the same sed
# expansions as src/Makefile.am), producing the one-shot <ALGO>Data()
# convenience functions.
cmake_minimum_required(VERSION 3.13)
project(libmd C)

if(NOT LIBMD_SRC_DIR)
  message(FATAL_ERROR "LIBMD_SRC_DIR must point at the libmd sources")
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

set(_libmd_hdrs   md2 md4 md5 rmd160 sha1 sha2 sha2 sha2)
set(_libmd_names  MD2 MD4 MD5 RMD160 SHA1 SHA256 SHA384 SHA512)
set(_libmd_outs   md2hl md4hl md5hl rmd160hl sha1hl sha256hl sha384hl sha512hl)

list(LENGTH _libmd_hdrs _libmd_n)
math(EXPR _libmd_n "${_libmd_n} - 1")
foreach(i RANGE ${_libmd_n})
  list(GET _libmd_hdrs ${i} _hdr)
  list(GET _libmd_names ${i} _name)
  list(GET _libmd_outs ${i} _out)
  set(_sed -e "s/hashinc/${_hdr}.h/g" -e "s/HASH/${_name}/g")
  if(_name MATCHES "^SHA[0-9]+$" AND NOT _name STREQUAL "SHA1")
    list(APPEND _sed -e "s/SHA[0-9][0-9][0-9]_CTX/SHA2_CTX/g")
  endif()
  execute_process(
    COMMAND sed ${_sed} ${LIBMD_SRC_DIR}/src/helper.c
    OUTPUT_FILE ${CMAKE_CURRENT_BINARY_DIR}/${_out}.c
  )
  list(APPEND _libmd_generated ${CMAKE_CURRENT_BINARY_DIR}/${_out}.c)
endforeach()

add_library(md STATIC
  ${LIBMD_SRC_DIR}/src/md2.c
  ${LIBMD_SRC_DIR}/src/md4.c
  ${LIBMD_SRC_DIR}/src/md5.c
  ${LIBMD_SRC_DIR}/src/rmd160.c
  ${LIBMD_SRC_DIR}/src/sha1.c
  ${LIBMD_SRC_DIR}/src/sha2.c
  ${_libmd_generated}
)

target_include_directories(md PUBLIC
  ${CMAKE_CURRENT_BINARY_DIR}
  ${LIBMD_SRC_DIR}/include
)

install(TARGETS md ARCHIVE DESTINATION lib)
install(DIRECTORY ${LIBMD_SRC_DIR}/include/ DESTINATION include)
