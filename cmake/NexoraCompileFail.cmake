if(NEXORA_COMPILE_FAIL_RUN)
  execute_process(COMMAND "${CMAKE_COMMAND}" --build "${NEXORA_BINARY_DIR}" --target "${NEXORA_FAIL_TARGET}"
    RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE errors)
  string(APPEND output "\n${errors}")
  if(status EQUAL 0)
    message(FATAL_ERROR "Unexpected successful compilation: ${NEXORA_FAIL_TARGET}")
  endif()
  if(NOT status MATCHES "^[0-9]+$" OR
      output MATCHES "No such file or directory|file not found|undefined reference|unable to execute command|ninja: error|internal compiler error|PLEASE submit a bug report|Segmentation fault|Killed signal")
    message(FATAL_ERROR "Infrastructure failure is not a valid rejection:\n${output}")
  endif()
  if(output MATCHES "error:[^\r\n]*(${NEXORA_EXPECTED_ERROR})")
    if(NEXORA_EXPECT_DIAGNOSTIC_REJECTION)
      message(FATAL_ERROR "Caret-only text incorrectly accepted as the intended diagnostic:\n${output}")
    endif()
  elseif(NEXORA_EXPECT_DIAGNOSTIC_REJECTION AND output MATCHES "error:")
    message(STATUS "Unrelated rejection with caret-only expected text correctly refused")
    return()
  else()
    message(FATAL_ERROR "Expected compiler diagnostic '${NEXORA_EXPECTED_ERROR}' missing:\n${output}")
  endif()
  message(STATUS "Expected compilation rejection confirmed: ${NEXORA_FAIL_TARGET}")
  return()
endif()

include_guard(GLOBAL)

function(nexora_add_compile_fail target source)
  cmake_parse_arguments(PARSE_ARGV 2 ARG "EXPECT_DIAGNOSTIC_REJECTION" "" "")
  get_filename_component(source "${source}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
  file(STRINGS "${source}" first_line LIMIT_COUNT 1)
  if(NOT first_line MATCHES "^// expected-error: (.+)$")
    message(FATAL_ERROR "${source} must start with // expected-error: <regex>")
  endif()
  set(expected_error "${CMAKE_MATCH_1}")
  add_library(${target} OBJECT EXCLUDE_FROM_ALL "${source}")
  nexora_configure_internal(${target})
  add_test(NAME ${target} COMMAND "${CMAKE_COMMAND}"
    "-DNEXORA_COMPILE_FAIL_RUN=ON" "-DNEXORA_BINARY_DIR=${CMAKE_BINARY_DIR}"
    "-DNEXORA_EXPECT_DIAGNOSTIC_REJECTION=${ARG_EXPECT_DIAGNOSTIC_REJECTION}"
    "-DNEXORA_FAIL_TARGET=${target}" "-DNEXORA_EXPECTED_ERROR=${expected_error}"
    -P "${CMAKE_CURRENT_FUNCTION_LIST_FILE}")
  set_tests_properties(${target} PROPERTIES RUN_SERIAL TRUE LABELS compile_fail TIMEOUT 120)
endfunction()
