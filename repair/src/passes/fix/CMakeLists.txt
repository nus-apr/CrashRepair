add_library(crashrepairfix MODULE
  FixPass.cpp
)

target_include_directories(crashrepairfix
  PRIVATE
    ${LLVM_INCLUDE_DIRS}
    ${LLVMSUPERMUTATE_INCLUDE_DIRS}
    nlohmann_json::nlohmann_json
)

target_compile_definitions(crashrepairfix
  PUBLIC
    ${LLVM_DEFINITIONS}
)

target_compile_options(crashrepairfix
  PRIVATE
    -Wall -Werror -fno-rtti
)

target_link_libraries(crashrepairfix
  PUBLIC
    llvmsupermutate
    nlohmann_json::nlohmann_json
)

install(TARGETS crashrepairfix
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)
