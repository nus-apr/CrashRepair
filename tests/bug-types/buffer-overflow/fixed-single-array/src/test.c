#include <stdio.h>

void bad() {
  int x = 56;
  int n = 5;
  int arr[n];
  int val = arr[x];
  printf("index %d = %d", x, val);
}

int main() {
  bad();
}
