add_executable(wormhole-freerdp-host
  "${CMAKE_CURRENT_LIST_DIR}/main.c"
  "${CMAKE_CURRENT_LIST_DIR}/wire.c"
  "${CMAKE_CURRENT_LIST_DIR}/surface.c")
set_target_properties(wormhole-freerdp-host PROPERTIES
  C_STANDARD 11 RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/wormhole-surface")
if(APPLE)
  target_sources(wormhole-freerdp-host PRIVATE "${CMAKE_CURRENT_LIST_DIR}/clipboard.m")
  set_source_files_properties("${CMAKE_CURRENT_LIST_DIR}/clipboard.m" PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
  target_link_libraries(wormhole-freerdp-host PRIVATE "-framework AppKit")
else()
  target_sources(wormhole-freerdp-host PRIVATE "${CMAKE_CURRENT_LIST_DIR}/clipboard_stub.c")
endif()
target_link_libraries(wormhole-freerdp-host PRIVATE freerdp-client freerdp winpr)
install(TARGETS wormhole-freerdp-host RUNTIME DESTINATION bin)
