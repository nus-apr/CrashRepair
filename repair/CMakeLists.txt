cmake_minimum_required(VERSION 3.13)
project(crashrepair
  VERSION 0.1
  DESCRIPTION "Automatic repair of C security vulnerabilities"
  LANGUAGES CXX
)

include(GNUInstallDirs)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM: ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
message(STATUS "Using LLVM libs: ${LLVM_LIBRARY_DIRS}")

# NOTE since this isn't a reusable library, we probably don't need this
set(CRASHREPAIR_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include)
install(DIRECTORY ${CRASHREPAIR_INCLUDE_DIRS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

add_subdirectory(extern)
# add_subdirectory(lib)
add_subdirectory(src)
