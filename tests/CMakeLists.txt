cmake_minimum_required(VERSION 4.0)
foreach(dimension IN ITEMS unit consteval compile_fail integration lifecycle scenario e2e)
  add_subdirectory(${dimension})
endforeach()
