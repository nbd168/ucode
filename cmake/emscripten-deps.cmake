# External dependencies for the emscripten/wasm32 build.
#
# The emscripten sysroot ships neither json-c nor libmd, so both are
# fetched and built here (included from CMakeLists.txt when UCODE_WASM
# is on; toolchain files cannot host this because they are re-included
# by every try_compile() probe build).
#
# json-c uses its own CMake build with two overrides:
#   -Wno-macro-redefined  its math_compat.h redefines NAN/INFINITY/isnan/
#                         isinf, which emscripten's clang already provides
#                         (a warning with plain emcc, an error under its
#                         -Werror)
#   -DHAVE_SNPRINTF=1     its snprintf feature check is gated on
#                         "UNIX OR MINGW OR CYGWIN", which the Generic
#                         (wasm32) system does not match
#
# libmd is autotools-only, so the cmake/deps/libmd wrapper CMakeLists
# compiles its sources directly.

include(ExternalProject)

set(UCODE_DEPS_PREFIX ${CMAKE_BINARY_DIR}/deps)

# The imported targets below reference these include directories, which
# only get their contents when the external projects build; create them
# now so CMake's generate-time path validation passes.
file(MAKE_DIRECTORY ${UCODE_DEPS_PREFIX}/json-c/dist/include)
file(MAKE_DIRECTORY ${UCODE_DEPS_PREFIX}/libmd/dist/include)

set(_ucode_toolchain_args "")
if(CMAKE_TOOLCHAIN_FILE)
  list(APPEND _ucode_toolchain_args -DCMAKE_TOOLCHAIN_FILE:FILEPATH=${CMAKE_TOOLCHAIN_FILE})
endif()

# ---------------------------------------------------------------------------
# json-c
# ---------------------------------------------------------------------------
ExternalProject_Add(json-c-build
  PREFIX ${UCODE_DEPS_PREFIX}/json-c
  GIT_REPOSITORY https://github.com/json-c/json-c.git
  GIT_TAG json-c-0.18-20240915
  GIT_SHALLOW 1
  CMAKE_ARGS
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    ${_ucode_toolchain_args}
    -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
    -DCMAKE_C_FLAGS:STRING=-Wno-macro-redefined
  CMAKE_CACHE_ARGS
    -DCMAKE_INSTALL_PREFIX:STRING=${UCODE_DEPS_PREFIX}/json-c/dist
    -DCMAKE_INSTALL_LIBDIR:STRING=lib
    -DBUILD_SHARED_LIBS:STRING=OFF
    -DBUILD_TESTING:STRING=OFF
    -DDISABLE_EXTRA_LIBS:STRING=ON
    -DHAVE_SNPRINTF:STRING=1
  UPDATE_COMMAND ""
)

add_library(libjson-c STATIC IMPORTED GLOBAL)
set_property(TARGET libjson-c PROPERTY IMPORTED_LOCATION ${UCODE_DEPS_PREFIX}/json-c/dist/lib/libjson-c.a)
set_property(TARGET libjson-c PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${UCODE_DEPS_PREFIX}/json-c/dist/include)
add_dependencies(libjson-c json-c-build)

# ---------------------------------------------------------------------------
# libmd
# ---------------------------------------------------------------------------
ExternalProject_Add(libmd-build
  PREFIX ${UCODE_DEPS_PREFIX}/libmd
  GIT_REPOSITORY https://git.hadrons.org/git/libmd.git
  GIT_TAG 1.0.4
  GIT_SHALLOW 1
  CONFIGURE_COMMAND ${CMAKE_COMMAND}
    -S ${CMAKE_CURRENT_SOURCE_DIR}/cmake/deps/libmd
    -B ${UCODE_DEPS_PREFIX}/libmd/build
    ${_ucode_toolchain_args}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DLIBMD_SRC_DIR=${UCODE_DEPS_PREFIX}/libmd/src/libmd-build
    -DCMAKE_INSTALL_PREFIX=${UCODE_DEPS_PREFIX}/libmd/dist
  BUILD_COMMAND ${CMAKE_COMMAND} --build ${UCODE_DEPS_PREFIX}/libmd/build
  INSTALL_COMMAND ${CMAKE_COMMAND} --install ${UCODE_DEPS_PREFIX}/libmd/build
  UPDATE_COMMAND ""
)

add_library(libmd STATIC IMPORTED GLOBAL)
set_property(TARGET libmd PROPERTY IMPORTED_LOCATION ${UCODE_DEPS_PREFIX}/libmd/dist/lib/libmd.a)
set_property(TARGET libmd PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${UCODE_DEPS_PREFIX}/libmd/dist/include)
add_dependencies(libmd libmd-build)
