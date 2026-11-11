include_guard(GLOBAL)
include("${CMAKE_CURRENT_LIST_DIR}/NexoraDependencies.cmake")

set(NEXORA_INTERFACE_TARGETS "")
foreach(layer IN ITEMS error bytes http tls http1 http2 websocket inbox dispatch socket pool client server)
  add_library(nexora_${layer} INTERFACE)
  add_library(nexora::${layer} ALIAS nexora_${layer})
  set_target_properties(nexora_${layer} PROPERTIES EXPORT_NAME ${layer})
  target_compile_features(nexora_${layer} INTERFACE cxx_std_26)
  target_include_directories(nexora_${layer} INTERFACE
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")
  target_compile_options(nexora_${layer} INTERFACE
    "$<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions;-fno-rtti>"
    "$<$<COMPILE_LANG_AND_ID:CXX,GNU>:-freflection;-Wno-psabi>"
    "$<$<COMPILE_LANG_AND_ID:CXX,Clang,AppleClang>:-freflection-latest;-stdlib=libc++>")
  target_link_options(nexora_${layer} INTERFACE
    "$<$<LINK_LANG_AND_ID:CXX,GNU>:-freflection>"
    "$<$<LINK_LANG_AND_ID:CXX,Clang,AppleClang>:-freflection-latest;-stdlib=libc++>")
  list(APPEND NEXORA_INTERFACE_TARGETS nexora_${layer})
endforeach()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND NEXORA_TOOLCHAIN_NAME STREQUAL "gcc-glibc")
  target_link_options(nexora_error INTERFACE
    "$<BUILD_INTERFACE:-Wl,-rpath,$ENV{HOME}/.local/toolchain/gcc-glibc/x86_64-unknown-linux-gnu/lib64>")
endif()

target_link_libraries(nexora_error INTERFACE uarch::uarch)
target_link_libraries(nexora_bytes INTERFACE nexora::error)
target_link_libraries(nexora_http INTERFACE nexora::bytes)
target_link_libraries(nexora_tls INTERFACE nexora::http AWS::ssl AWS::crypto)
target_link_libraries(nexora_http1 INTERFACE nexora::http)
target_link_libraries(nexora_http2 INTERFACE nexora::http uarch::uarch)
target_link_libraries(nexora_websocket INTERFACE nexora::http AWS::crypto)
target_link_libraries(nexora_inbox INTERFACE nexora::http nexora::websocket)
target_link_libraries(nexora_dispatch INTERFACE nexora::error uring::uring)
target_link_libraries(nexora_socket INTERFACE nexora::dispatch nexora::tls cares::cares uring::uring)
target_link_libraries(nexora_pool INTERFACE nexora::http cares::cares)
target_link_libraries(nexora_client INTERFACE
  nexora::socket nexora::pool nexora::inbox nexora::http1 nexora::http2 nexora::websocket nexora::dispatch cares::cares)
target_link_libraries(nexora_server INTERFACE nexora::client)

add_library(nexora INTERFACE)
add_library(nexora::nexora ALIAS nexora)
target_link_libraries(nexora INTERFACE ${NEXORA_INTERFACE_TARGETS})

function(nexora_configure_internal target)
  cmake_parse_arguments(PARSE_ARGV 1 ARG "NO_SANITIZERS" "" "")
  target_link_libraries(${target} PRIVATE nexora::nexora)
  uarch_configure_runtime(${target})
  if(NEXORA_TOOLCHAIN_NAME STREQUAL "clang-glibc")
    # uarch selects the sysroot loader reported by Clang. This toolchain links host glibc.
    target_link_options(${target} PRIVATE "LINKER:--dynamic-linker,/lib64/ld-linux-x86-64.so.2")
  endif()
  nexora_enable_warnings(${target})
  if(NOT ARG_NO_SANITIZERS)
    nexora_enable_sanitizers(${target})
  endif()
endfunction()

function(nexora_add_test target)
  add_executable(${target} ${ARGN})
  nexora_configure_internal(${target})
  add_test(NAME ${target} COMMAND ${target})
endfunction()
