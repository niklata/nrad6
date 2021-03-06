project (nrad6)

cmake_minimum_required (VERSION 2.6)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=gnu99 -pedantic -Wall -Wextra -Wformat=2 -Wformat-nonliteral -Wformat-security -Wpointer-arith -Wno-unused-parameter -DNDHS_BUILD")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -std=gnu++14 -pedantic -Wall -Wextra -Wformat=2 -Wformat-nonliteral -Wformat-security -Wpointer-arith -Wno-unused-parameter -DNDHS_BUILD")

if (WIN32)
  set(OSNAME "Win32")
else()
execute_process(
  COMMAND uname
  COMMAND tr "\n" " "
  COMMAND sed "s/ //"
  OUTPUT_VARIABLE OSNAME
  )
endif()
#message("OSNAME: '${OSNAME}'")

if (${OSNAME} STREQUAL "Linux")
  message("Detected that the current host is a Linux system.")
  execute_process(
    COMMAND uname -r
    COMMAND tr "\n" " "
    COMMAND sed "s/ //"
    OUTPUT_VARIABLE LINUX_VERSION
    )
else()
  message("nrad6 requires a Linux host system.")
  return()
endif()

include_directories("${PROJECT_SOURCE_DIR}"
                    "${PROJECT_SOURCE_DIR}/ncmlib"
                    "${PROJECT_SOURCE_DIR}/cppformat")
add_subdirectory(ncmlib)
add_subdirectory(cppformat)

find_package( Boost COMPONENTS system )
link_directories ( ${Boost_LIBRARY_DIRS} )
include_directories ( ${Boost_INCLUDE_DIRS} )
find_package(Threads)

set(RAGEL_CFG ${CMAKE_CURRENT_BINARY_DIR}/cfg.cpp)
set(RAGEL_DYNLEASE ${CMAKE_CURRENT_BINARY_DIR}/dynlease.cpp)

find_program(RAGEL ragel)
add_custom_command(
  OUTPUT ${RAGEL_CFG}
  COMMAND ${RAGEL} -G2 -o ${RAGEL_CFG} cfg.rl
  DEPENDS cfg.rl
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "Compiling Ragel state machine: cfg.rl"
  VERBATIM
  )
add_custom_command(
  OUTPUT ${RAGEL_DYNLEASE}
  COMMAND ${RAGEL} -G2 -o ${RAGEL_DYNLEASE} dynlease.rl
  DEPENDS dynlease.rl
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMENT "Compiling Ragel state machine: dynlease.rl"
  VERBATIM
  )

file(GLOB NRAD6_SRCS_C "*.c")
file(GLOB NRAD6_SRCS_CPP "*.cpp")
list(APPEND NRAD6_SRCS ${NRAD6_SRCS_C} ${NRAD6_SRCS_CPP})

add_executable(nrad6 ${RAGEL_CFG} ${RAGEL_DYNLEASE} ${NRAD6_SRCS})
target_link_libraries(nrad6 ${CMAKE_THREAD_LIBS_INIT} ${Boost_LIBRARIES} ncmlib cppformat)

