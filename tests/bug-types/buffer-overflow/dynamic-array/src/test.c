#include <stdio.h>

void bad() {
  int x = 56;
  int n = 10;
  int arr[n];
  arr[1] = 2;
  arr[0] = 3;
  printf("%d %d %d", arr[0], arr[1], arr[2]);
  int val = arr[x];
}

int main() {
  bad();
}
