#include <stdio.h>

#ifndef TRIDENT_OUTPUT
#define TRIDENT_OUTPUT(id, typestr, value) value
#endif

int main(int argc, char *argv[]) {
  int x = atoi(argv[1]);
  int res, y;
  y = x - 1;
  klee_print_expr("y", y);
  res = 1000 / y;
  return 0;
}
