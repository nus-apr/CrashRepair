#include <stdio.h>
#include <limits.h>

void bad(int m, int n) {
  int z = 4;
  z = -m - n;
}


int main(int argc, char *argv[]) {
  int x = atoi(argv[1]);
  int a = INT_MAX ;
  bad(x, a);
  return 0;
}
