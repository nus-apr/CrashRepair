add_library(crashrepairlib
  Expr/ClangToExprConverter.cpp
  Expr/ExprGenerator.cpp
  Expr/ExprToZ3Converter.cpp
  Expr/Parser.cpp
  DiffGenerator.cpp
  ProgramMutator.cpp
  ProgramStates.cpp
  FixLocationLinter.cpp
  Utils.cpp
)

add_executable(crashrepairfix
  crashrepairfix.cpp
  Expr/ClangToExprConverter.cpp
  Expr/ExprGenerator.cpp
  Expr/ExprToZ3Converter.cpp
  Expr/Parser.cpp
  DiffGenerator.cpp
  ProgramMutator.cpp
  ProgramStates.cpp
  FixLocationLinter.cpp
  Utils.cpp
)

add_executable(_crepairparse
  crashrepairparse.cpp
  Expr/ClangToExprConverter.cpp
  Expr/ExprGenerator.cpp
  Expr/ExprToZ3Converter.cpp
  Expr/Parser.cpp
  DiffGenerator.cpp
  ProgramMutator.cpp
  ProgramStates.cpp
  FixLocationLinter.cpp
  Utils.cpp
)

llvm_map_components_to_libnames(CRASHREPAIRFIX_LLVM_LIBS
  Demangle
)

set_target_properties(crashrepairlib
  PROPERTIES
    CXX_STANDARD 17
    CMAKE_CXX_STANDARD_REQUIRED ON
)
target_link_libraries(crashrepairlib PRIVATE
  ${Z3_LIBRARY}
  ${CRASHREPAIRFIX_LLVM_LIBS}
  ${CLANG_LIBS}
  taocpp::pegtl
  nlohmann_json::nlohmann_json
  spdlog::spdlog
)
target_compile_options(crashrepairlib PRIVATE
  -Wall -Werror -Wno-error=comment -fno-rtti
)
target_include_directories(crashrepairlib
  PUBLIC
    ${CLANG_INCLUDE_DIRS}
    ${LLVM_INCLUDE_DIRS}
    ${Z3_INCLUDE_DIRS}
    taocpp::pegtl
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    ../../include
    ../../extern/dtl/include
)

set_target_properties(_crepairparse
  PROPERTIES
    CXX_STANDARD 17
    CMAKE_CXX_STANDARD_REQUIRED ON
)
target_link_libraries(_crepairparse PRIVATE
  ${Z3_LIBRARY}
  ${CRASHREPAIRFIX_LLVM_LIBS}
  ${CLANG_LIBS}
  taocpp::pegtl
  nlohmann_json::nlohmann_json
  spdlog::spdlog
)
target_compile_options(_crepairparse PRIVATE
  -Wall -Werror -Wno-error=comment -fno-rtti
)
target_include_directories(_crepairparse
  PUBLIC
    ${CLANG_INCLUDE_DIRS}
    ${LLVM_INCLUDE_DIRS}
    ${Z3_INCLUDE_DIRS}
    taocpp::pegtl
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    ../../include
    ../../extern/dtl/include
)

set_target_properties(crashrepairfix
  PROPERTIES
    CXX_STANDARD 17
    CMAKE_CXX_STANDARD_REQUIRED ON
#    LINK_SEARCH_START_STATIC ON
#    LINK_SEARCH_END_STATIC ON
)
target_link_libraries(crashrepairfix PRIVATE
  ${Z3_LIBRARY}
  ${CRASHREPAIRFIX_LLVM_LIBS}
  ${CLANG_LIBS}
  taocpp::pegtl
  nlohmann_json::nlohmann_json
  spdlog::spdlog
)
target_compile_options(crashrepairfix PRIVATE
  -Wall -Werror -Wno-error=comment -fno-rtti
)
# target_link_options(crashrepairfix PRIVATE
#   -static-libgcc -static-libstdc++ -static -Wl,--copy-dt-needed-entries
# )
target_compile_definitions(crashrepairfix
  PUBLIC ${CLANG_DEFINITIONS} ${LLVM_DEFINITIONS}
)
target_include_directories(crashrepairfix
  PUBLIC
    ${CLANG_INCLUDE_DIRS}
    ${LLVM_INCLUDE_DIRS}
    ${Z3_INCLUDE_DIRS}
    taocpp::pegtl
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    ../../include
    ../../extern/dtl/include
)

install(
  TARGETS crashrepairfix _crepairparse
  DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

# TODO we need to install clang's headers!
