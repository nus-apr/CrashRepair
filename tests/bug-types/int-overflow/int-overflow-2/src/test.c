#include <stdio.h>
#include <limits.h>

void bad(int x, int y) {
  int z = 4;
  z = x + y;
}


int main(int argc, char *argv[]) {
  int x = atoi(argv[1]);
  int a = INT_MAX ;
  bad(x, a);
  return 0;
}
