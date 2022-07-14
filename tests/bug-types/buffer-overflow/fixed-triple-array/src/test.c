#include <stdio.h>

void bad() {
  int x = 0, y = 1, z = 56;
  int m = 1, n = 2, o = 5;
  int arr[m][n][o];
  int val = arr[x][y][z];
  printf("index %d = %d", x, val);
}

int main() {
  bad();
}
