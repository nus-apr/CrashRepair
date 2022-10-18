#include <crashrepairfix/Expr/Parser.h>

#include <iostream>

#include <spdlog/spdlog.h>

int main(int argc, const char **argv) {
  spdlog::set_level(spdlog::level::debug);

  auto expr = crashrepairfix::parse(argv[1]);
  if (expr) {
    spdlog::info("expression: {}", expr->toString());
  }

  return 0;
}
