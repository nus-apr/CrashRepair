#include <stdio.h>

int main(int argc, char *argv[]) {
  int x = atoi(argv[1]);
  int y = 1;
  int res;
  while (x > 0){
    x = x - 1;
    res = 1000 / x;
  }

  return 0;
}








