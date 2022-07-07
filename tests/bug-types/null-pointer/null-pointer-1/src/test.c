#include <stdio.h>
#include <limits.h>
#include <stddef.h>

int get_value(int *ptr) {
  int value = *ptr; /* Dereferencing happens here */
  return value;
}

int main() {
  int * pointer = NULL;
  int x = get_value(pointer);
}