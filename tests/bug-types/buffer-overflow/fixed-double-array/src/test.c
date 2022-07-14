#include <stdio.h>

void bad() {
  int x = 56, y = 1;
  int a = 2, b = 5;
  int arr[a][b];
  int val = arr[y][x];
  printf("index %d = %d", x, val);
}

int main() {
  bad();
}
