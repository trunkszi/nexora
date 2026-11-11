cmake_minimum_required(VERSION 4.0)
nexora_add_compile_fail(nexora_smoke_compile_fail smoke_compile_fail.cc)
nexora_add_compile_fail(
  nexora_invalid_header_name_compile_fail
  http/invalid_header_name_compile_fail.cc
)
nexora_add_compile_fail(
  nexora_invalid_header_value_compile_fail
  http/invalid_header_value_compile_fail.cc
)
nexora_add_compile_fail(
  nexora_invalid_http2_header_compile_fail
  http/invalid_http2_header_compile_fail.cc
)
nexora_add_compile_fail(
  nexora_duplicate_reflected_header_compile_fail
  http/duplicate_reflected_header_compile_fail.cc
)
