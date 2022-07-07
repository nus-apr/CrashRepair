add_executable(crashrepairfix
  crashrepairfix.cpp
  ProgramMutator.cpp
  Utils.cpp
)

llvm_map_components_to_libnames(CRASHREPAIRFIX_LLVM_LIBS
  Demangle
)

set_target_properties(crashrepairfix
  PROPERTIES
    CXX_STANDARD 14
    CMAKE_CXX_STANDARD_REQUIRED ON
    LINK_SEARCH_START_STATIC ON
    LINK_SEARCH_END_STATIC ON
)
target_link_libraries(crashrepairfix PRIVATE
  ${CRASHREPAIRFIX_LLVM_LIBS}
  ${CLANG_LIBS}
  nlohmann_json::nlohmann_json
  fmt::fmt-header-only
  spdlog::spdlog
)
target_compile_options(crashrepairfix PRIVATE
  -Wall -Werror -fno-rtti
)
target_link_options(crashrepairfix PRIVATE
  -static-libgcc -static-libstdc++ -static
)
target_compile_definitions(crashrepairfix
  PUBLIC ${CLANG_DEFINITIONS} ${LLVM_DEFINITIONS}
)
target_include_directories(crashrepairfix
  PUBLIC
    ${CLANG_INCLUDE_DIRS}
    ${LLVM_INCLUDE_DIRS}
    nlohmann_json::nlohmann_json
    fmt::fmt
    spdlog::spdlog
    ../../include
)

install(
  TARGETS crashrepairfix
  DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

# TODO we need to install clang's headers!
