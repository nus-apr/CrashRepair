#include <stdio.h>

int main(int argc, char *argv[]) {
  int a = atoi(argv[1]);
  int x = 1;
  int y = 1;
  int res, z;
  if (a > 5)
    y = y - 1;
  else
    x = x -1;
  z = x * y;
  res = 1000 / z;
  return 0;
}








