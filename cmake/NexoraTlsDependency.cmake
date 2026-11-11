# Macro so find_dependency()'s return() leaves the caller (nexora-config.cmake),
# not this file. No include_guard: a later find_package(nexora) must run again.
if(NOT COMMAND nexora_find_tls_dependency)
  macro(nexora_find_tls_dependency)
    if(NEXORA_CONSUMER_CONFIG)
      unset(NEXORA_CONSUMER_CONFIG)
      find_dependency(ssl CONFIG)
    else()
      unset(NEXORA_CONSUMER_CONFIG)
      find_package(ssl CONFIG REQUIRED)
    endif()
    if(NOT TARGET AWS::ssl OR NOT TARGET AWS::crypto)
      message(FATAL_ERROR "nexora requires AWS-LC targets AWS::ssl and AWS::crypto")
    endif()
    # OpenSSL:: names are compatibility aliases for AWS-LC. Establish them before later
    # packages run, and never point AWS:: at another provider.
    if(NOT TARGET OpenSSL::SSL)
      add_library(OpenSSL::SSL ALIAS AWS::ssl)
    endif()
    if(NOT TARGET OpenSSL::Crypto)
      add_library(OpenSSL::Crypto ALIAS AWS::crypto)
    endif()
  endmacro()
endif()

if(NOT NEXORA_CONSUMER_CONFIG)
  nexora_find_tls_dependency()
endif()
