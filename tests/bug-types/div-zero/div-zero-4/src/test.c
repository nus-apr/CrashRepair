#include <stdio.h>

int main(int argc, char *argv[]) {
  int x = atoi(argv[1]);
  int y = 1;
  int res, z;
  if (x > 5)
    y = y - 1;
  else
    y = y + 2;

  z = x * y;
  res = 1000 / z;
  return 0;
}








