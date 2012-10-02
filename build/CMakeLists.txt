cmake_minimum_required (VERSION 2.6 FATAL_ERROR)

set (PROJECT ../bin/dhcpd-detector)
project (${PROJECT})

set (HEADERS
        ../src/dhcpd-detector.h
        ../src/gopt.h
        ../src/sum.h
        )

set (SOURCES
        ../src/dhcpd-detector.c
        ../src/gopt.c
        )

#set (Boost_USE_STATIC_LIBS TRUE)
#set (Boost_USE_MULTITHREADED TRUE)

#find_package (Boost REQUIRED COMPONENTS system thread regex program_options filesystem)

#link_directories (${Boost_LIBRARY_DIRS})
#include_directories (${Boost_INCLUDE_DIRS})

macro (add_app_executable BUILD_TYPE)
  add_executable (${PROJECT}-${BUILD_TYPE} ${HEADERS} ${SOURCES})
  if ("${BUILD_TYPE}" STREQUAL "debug")
    set_target_properties (${PROJECT}-${BUILD_TYPE} PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS_DEBUG}")
  elseif ("${BUILD_TYPE}" STREQUAL "release")
    set_target_properties (${PROJECT}-${BUILD_TYPE} PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS_RELEASE}")
  endif()
#  target_link_libraries (${PROJECT}-${BUILD_TYPE} ${Boost_LIBRARIES} pthread)
endmacro()

add_app_executable ("debug")
add_app_executable ("release")

