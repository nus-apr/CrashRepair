#include <stdio.h>

int main(int argc, char *argv[]) {
  int varA = atoi(argv[1]);
  int varB = atoi(argv[2]);
  int res, div;

  if (varA > 5)
    div = varA - 1;
  else
    div = varA + 2;
  div = varA * varB;
  res = 1000 / div;
  return 0;
}








