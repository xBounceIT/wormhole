# libovpn_shim — static library that wraps OpenVPN3-core for CGO consumption by the
# wormhole-ovpnproxy sidecar. The build script uses the architecture-specific
# ovpn_shim/build/<arch>/libovpn_shim.a to prevent cross-architecture cache reuse.
#
# Prerequisites:
#   - C++17 toolchain on PATH (MinGW-w64 g++ for CGO compatibility; MSVC also works)
#   - CMake 3.20+
#   - vcpkg (recommended) OR manual installs of asio, jsoncpp, lz4, mbedtls, xxhash,
#     tap-windows6 (header-only, used unconditionally by OpenVPN3 even when we bypass
#     the TAP driver via ExternalTun::Factory)
#   - third_party/openvpn3 populated (release/3.9 submodule)
#   - third_party/mbedtls populated (v3.6.6 LTS submodule, with `framework/` recurse-init)
#
# Build flags are delegated to OpenVPN3's own `add_core_dependencies()` macro in
# cmake/findcoredeps.cmake — that's the canonical source of truth for what every
# OpenVPN3 translation unit needs (USE_ASIO, HAVE_LZ4, ASIO_STANDALONE,
# ASIO_DISABLE_LOCAL_SOCKETS, _WIN32_WINNT, tap-windows component id, MinGW big-obj,
# Windows link libs, etc.). Re-deriving those flags by hand drifts every release.
#
# See README.md for the full toolchain setup walk-through.

cmake_minimum_required(VERSION 3.20)
project(ovpn_shim CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Source files for the shim itself.
add_library(ovpn_shim STATIC shim.cc)
target_include_directories(ovpn_shim PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# OpenVPN3 + mbedTLS: gated on submodule presence. When absent, the shim builds with
# HAVE_OPENVPN3=0 stubs so the CGO link still succeeds.
set(OPENVPN3_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/openvpn3")
set(MBEDTLS_DIR  "${CMAKE_CURRENT_SOURCE_DIR}/../third_party/mbedtls")
if(EXISTS "${OPENVPN3_DIR}/client/ovpncli.hpp" AND EXISTS "${MBEDTLS_DIR}/include/mbedtls/ssl.h")
    message(STATUS "ovpn_shim: building with OpenVPN3 (${OPENVPN3_DIR})")

    # mbedTLS first — its CMake exports `mbedTLS::mbedTLS` only after add_subdirectory.
    set(ENABLE_PROGRAMS OFF CACHE BOOL "")
    set(ENABLE_TESTING  OFF CACHE BOOL "")
    add_subdirectory(${MBEDTLS_DIR} third_party_mbedtls EXCLUDE_FROM_ALL)

    # OpenVPN3's findcoredeps macro wants a CMake target `mbedTLS::mbedTLS`. mbedtls's
    # own CMake exports `mbedtls` / `mbedx509` / `mbedcrypto`. Bridge by aliasing.
    if(NOT TARGET mbedTLS::mbedTLS)
        add_library(mbedTLS::mbedTLS INTERFACE IMPORTED)
        target_link_libraries(mbedTLS::mbedTLS INTERFACE mbedtls mbedx509 mbedcrypto)
        # findcoredeps calls find_package(mbedTLS REQUIRED). Short-circuit it by setting
        # _FOUND so the find_package call below succeeds against our alias.
        set(mbedTLS_FOUND TRUE CACHE BOOL "" FORCE)
        # find_package's REQUIRED mode also wants a config file in some setups; set a
        # known mbedTLS root so the package config search succeeds quietly.
        set(MBEDTLS_INCLUDE_DIR ${MBEDTLS_DIR}/include CACHE PATH "" FORCE)
        set(MBEDTLS_LIBRARY mbedtls CACHE STRING "" FORCE)
        set(MBEDX509_LIBRARY mbedx509 CACHE STRING "" FORCE)
        set(MBEDCRYPTO_LIBRARY mbedcrypto CACHE STRING "" FORCE)
    endif()

    # USE_MBEDTLS gates findcoredeps's SSL library selection.
    set(USE_MBEDTLS ON CACHE BOOL "" FORCE)

    # Pull in OpenVPN3's canonical core-deps helper. This sets USE_ASIO, HAVE_LZ4,
    # ASIO_STANDALONE, ASIO_DISABLE_LOCAL_SOCKETS, _WIN32_WINNT=0x0600, the
    # tap-windows component id, MinGW big-obj flag, Windows system libs, etc.
    list(APPEND CMAKE_MODULE_PATH ${OPENVPN3_DIR}/cmake)
    include(${OPENVPN3_DIR}/cmake/findcoredeps.cmake)

    add_core_dependencies(ovpn_shim)
    add_json_library(ovpn_shim)

    # OpenVPN3 includes for our shim's own translation unit.
    target_include_directories(ovpn_shim PUBLIC
        ${OPENVPN3_DIR}
        ${OPENVPN3_DIR}/client
        ${MBEDTLS_DIR}/include
    )

    # OPENVPN_EXTERNAL_TUN_FACTORY enables the ExternalTun::Factory base class on
    # ClientAPI::OpenVPNClient and routes TUN setup through our custom TunClient
    # (see shim.cc — the documented embedder hook for userspace bidirectional TUN).
    # This is the KEY flag for our use case; everything else is delegated to
    # add_core_dependencies above.
    # (HAVE_OPENVPN3 is set by shim.cc itself via __has_include — the include
    # paths above make that check pass.)
    target_compile_definitions(ovpn_shim PUBLIC OPENVPN_EXTERNAL_TUN_FACTORY=1)

    # OpenVPN3's ovpncli.cpp is the entry point class implementation. It isn't built
    # into a library by upstream — clients are expected to compile it into their own
    # binary. Add it as a source so the linker resolves OpenVPNClient's methods.
    target_sources(ovpn_shim PRIVATE
        ${OPENVPN3_DIR}/client/ovpncli.cpp
    )
else()
    message(WARNING "ovpn_shim: openvpn3 and/or mbedtls submodules not populated; "
            "building HAVE_OPENVPN3=0 stub. Run `git submodule update --init --recursive` "
            "and rebuild to enable the real path. See README.md for the full toolchain "
            "list (vcpkg recommended).")
endif()
