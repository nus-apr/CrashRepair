enable_testing()

add_executable(parser_test
  parser_test.cpp
)
target_link_libraries(parser_test
  crashrepairlib
  GTest::gtest_main
  spdlog::spdlog
)

# TODO set CRASHREPAIRFIX_DEFINITIONS
set_target_properties(parser_test
  PROPERTIES
    CXX_STANDARD 17
    CMAKE_CXX_STANDARD_REQUIRED ON
)

# # TODO set CRASHREPAIRFIX_INCLUDE_DIRS
# target_include_directories(parser_test
#   PUBLIC
#     ${CLANG_INCLUDE_DIRS}
#     ${LLVM_INCLUDE_DIRS}
#     ${Z3_INCLUDE_DIRS}
#     taocpp::pegtl
#     nlohmann_json::nlohmann_json
#     spdlog::spdlog
#     ../../include
#     ../../extern/dtl/include
# )

include(GoogleTest)
gtest_discover_tests(parser_test)
