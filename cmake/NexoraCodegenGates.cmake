include_guard(GLOBAL)

# Native codegen evidence is compiled separately from instrumented tests.
function(nexora_add_codegen_probes target)
  add_library(${target} OBJECT ${ARGN})
  nexora_configure_internal(${target} NO_SANITIZERS)
  set_target_properties(${target} PROPERTIES INTERPROCEDURAL_OPTIMIZATION FALSE)
  target_compile_options(${target} PRIVATE -O3 -fno-lto)
  # Global coverage settings must not change native instruction evidence.
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(${target} PRIVATE -fno-profile-instr-generate -fno-coverage-mapping)
  elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${target} PRIVATE -fno-profile-arcs -fno-test-coverage -fno-profile-generate)
  endif()
endfunction()
