#include <stdio.h>
#include <limits.h>
#include <stddef.h>

void reset_zero(int *target, int size) {
  memset((void *)(target), 0, (size_t)(size));
}

int main() {
  int * pointer;
  int size = 10;
  reset_zero(pointer, size);
}
