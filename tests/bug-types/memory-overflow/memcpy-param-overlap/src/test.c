#include <stdio.h>
#include <limits.h>
#include <stddef.h>

void copy_zero(int *source, int*target, int size) {
  memcpy(source, target, size);
}

int main() {
  char buffer[10];
  char *ptr_a = &buffer[3];
  char *ptr_b = &buffer[6];
  int count = 5;
  copy_zero(ptr_a, ptr_b, count);
}
