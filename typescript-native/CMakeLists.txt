# Copyright (c) AyanWorks. Licensed under the MIT License.
# Builds the @didx509/native Node-API addon around Microsoft's didx509cpp.
cmake_minimum_required(VERSION 3.18)
project(didx509_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# node-gyp-build looks for compiled binaries under build/Release.
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Release")

# Multi-config generators (Visual Studio, Xcode) append the configuration
# name to the output directories above, producing build/Release/<Config> —
# which node-gyp-build does not look in. Pin every configuration to
# build/Release explicitly. (No-op for single-config generators such as
# Makefiles and Ninja: CMAKE_CONFIGURATION_TYPES is empty there.)
foreach(config IN LISTS CMAKE_CONFIGURATION_TYPES)
  string(TOUPPER "${config}" config_upper)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${config_upper}
    "${CMAKE_BINARY_DIR}/Release")
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${config_upper}
    "${CMAKE_BINARY_DIR}/Release")
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${config_upper}
    "${CMAKE_BINARY_DIR}/Release")
endforeach()

option(DIDX509_STATIC_OPENSSL
  "Prefer static OpenSSL libraries (required for redistributable prebuilds)" OFF)

# Help find_package(OpenSSL): prefer an explicit OPENSSL_ROOT_DIR, then the
# prefix built by scripts/build-openssl.cjs, then macOS Homebrew.
if(NOT OPENSSL_ROOT_DIR AND NOT DEFINED ENV{OPENSSL_ROOT_DIR})
  if(EXISTS "${CMAKE_SOURCE_DIR}/.openssl/include/openssl/ssl.h")
    set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/.openssl")
  elseif(APPLE)
    foreach(_prefix "/opt/homebrew/opt/openssl@3" "/usr/local/opt/openssl@3")
      if(EXISTS "${_prefix}/include/openssl/ssl.h")
        set(OPENSSL_ROOT_DIR "${_prefix}")
        break()
      endif()
    endforeach()
  endif()
endif()

if(DIDX509_STATIC_OPENSSL)
  # Same trick as upstream: search static archives before shared libraries.
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".lib" ".dylib" ".so")
endif()

# Upstream requires OpenSSL 3.3 or newer (libcrypto only).
find_package(OpenSSL 3.3 REQUIRED COMPONENTS Crypto)

if(NOT EXISTS "${CMAKE_SOURCE_DIR}/third_party/didx509cpp/didx509cpp.h")
  message(FATAL_ERROR
    "didx509cpp.h not found. Run: git submodule update --init")
endif()

# Report the exact upstream commit via didx509_version(). In a git checkout
# the submodule's HEAD is authoritative; in an npm tarball fall back to the
# DIDX509CPP_COMMIT file (kept fresh by `npm run sync:commit` + tests).
execute_process(
  COMMAND git -C "${CMAKE_SOURCE_DIR}/third_party/didx509cpp" rev-parse HEAD
  OUTPUT_VARIABLE DIDX509CPP_COMMIT
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
)
if(NOT DIDX509CPP_COMMIT AND EXISTS "${CMAKE_SOURCE_DIR}/DIDX509CPP_COMMIT")
  file(READ "${CMAKE_SOURCE_DIR}/DIDX509CPP_COMMIT" _didx509_commit_file)
  string(STRIP "${_didx509_commit_file}" DIDX509CPP_COMMIT)
endif()
if(NOT DIDX509CPP_COMMIT)
  set(DIDX509CPP_COMMIT "unknown")
endif()

# node-addon-api headers. Scripts/install.cjs passes the resolved path
# (robust against hoisting); the other candidates cover a nested install
# (this package's own node_modules) and a hoisted consumer root.
find_path(NODE_ADDON_API_INCLUDE_DIR napi.h
  PATHS
    "${NODE_ADDON_API_INCLUDE}"
    "${CMAKE_SOURCE_DIR}/node_modules/node-addon-api"
    "${CMAKE_SOURCE_DIR}/../node_modules/node-addon-api"
  NO_DEFAULT_PATH
)
if(NOT NODE_ADDON_API_INCLUDE_DIR)
  message(FATAL_ERROR
    "node-addon-api headers not found. Reinstall the package, or from a "
    "git checkout run: npm ci")
endif()

add_library(didx509_native SHARED
  native/addon.cpp
  shim/didx509_shim.cpp
)
set_target_properties(didx509_native PROPERTIES PREFIX "" SUFFIX ".node")

target_include_directories(didx509_native PRIVATE
  # OpenSSL's include dir MUST come first: the Node headers tarball that
  # cmake-js downloads bundles its own openssl/ tree (Node 20 ships
  # OpenSSL 3.0 headers), and plain -I dirs are searched before both
  # other -I dirs and -isystem dirs. With node headers first, didx509cpp's
  # "#error requires OpenSSL 3.3 or newer" fires even though configure
  # found a newer OpenSSL.
  "${OPENSSL_INCLUDE_DIR}"
  "${CMAKE_SOURCE_DIR}/third_party/didx509cpp"
  "${NODE_ADDON_API_INCLUDE_DIR}"
  "${CMAKE_JS_INC}"
)

target_compile_definitions(didx509_native PRIVATE
  NAPI_VERSION=8
  HAVE_OPENSSL
  DIDX509CPP_COMMIT="${DIDX509CPP_COMMIT}"
)

target_link_libraries(didx509_native PRIVATE OpenSSL::Crypto)

find_package(Threads REQUIRED)
target_link_libraries(didx509_native PRIVATE Threads::Threads ${CMAKE_DL_LIBS})

if(WIN32)
  target_link_libraries(didx509_native PRIVATE crypt32 ws2_32 "${CMAKE_JS_LIB}")
endif()
