# Languages must be enabled while configuring, before deferred target creation.
if(APPLE)
  enable_language(OBJC)
endif()
# A deferred add_subdirectory is forbidden by CMake. Include target commands in
# the root scope after FreeRDP has established its headers and dependency targets.
cmake_language(DEFER CALL include "${WORMHOLE_RDP_SURFACE_SOURCE}/target.cmake")
