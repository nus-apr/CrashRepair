#include <stdio.h>

int main(int argc, char *argv[]) {
  int x = atoi(argv[1]);
  int res, z;
  if (x > 5)
    z = x - 7;
  else
    z = x + 2;

  res = 1000 / z;
  return 0;
}








