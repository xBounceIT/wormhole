cmake_minimum_required(VERSION 3.20)
project(wormhole-freerdp-host C)
set(CMAKE_C_STANDARD 11)

# May be included in the existing FreeRDP build (including static/universal
# builds), or compiled against an already installed FreeRDP development SDK.
if(NOT TARGET freerdp-client)
  find_package(FreeRDP-Client3 3.33 CONFIG REQUIRED)
  find_package(FreeRDP3 3.33 CONFIG REQUIRED)
  find_package(WinPR3 3.33 CONFIG REQUIRED)
endif()
if(APPLE)
  enable_language(OBJC)
endif()
include(target.cmake)
