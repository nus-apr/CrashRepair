cmake_minimum_required(VERSION 3.13)
project(crashrepairfix CXX)

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

message(STATUS "Found LLVM: ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
message(STATUS "Using LLVM libs: ${LLVM_LIBRARY_DIRS}")

find_package(Clang REQUIRED clangTooling libClang)

set(CLANG_LIBS
  clangAST
  clangASTMatchers
  clangAnalysis
  clangBasic
  clangDriver
  clangEdit
  clangFrontend
  clangFrontendTool
  clangLex
  clangParse
  clangSema
  clangEdit
  clangRewrite
  clangRewriteFrontend
  clangStaticAnalyzerFrontend
  clangStaticAnalyzerCheckers
  clangStaticAnalyzerCore
  clangSerialization
  clangToolingCore
  clangTooling
  clangFormat
)

find_library(Z3_LIBRARY NAMES z3 DOC "Z3 libraries")
if (Z3_LIBRARIES)
    message(STATUS "Found Z3 libraries: ${Z3_LIBRARY}")
    link_libraries(${Z3_LIBRARY})
else ()
    message(FATAL "Could not find Z3 libraries")
endif ()

find_path(Z3_INCLUDE_DIRS NAMES z3++.h PATH_SUFFIXES z3 DOC "Z3 C header")
if (Z3_INCLUDE_DIRS)
    message(STATUS "Found Z3 include path: \"${Z3_INCLUDE_DIRS}\"")
else ()
    message(STATUS "Could not find Z3 include path")
endif ()

add_subdirectory(extern)
add_subdirectory(src)

