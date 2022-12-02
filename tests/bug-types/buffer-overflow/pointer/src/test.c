#include <stdio.h>
#include <stdlib.h>

int main() {
  int x = 11;
  int *arr = (int *) malloc(10);
  int val;
  int *ptr = arr + x;
  *ptr = 12;
  printf("index %d = %d", x, val);
}

