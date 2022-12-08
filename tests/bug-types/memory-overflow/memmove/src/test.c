#include <stdio.h>
#include <limits.h>
#include <stddef.h>

void copy_zero(int *source, int*target, int size) {
  memmove(source, target, size);
}

int main() {
  int *source = (int *)malloc(sizeof(int) * 5);
  memset(source, 0, 5);
  int *target = (int *)malloc(sizeof(int) * 5);
  int size = -100;
  copy_zero(source, target, size);
}
