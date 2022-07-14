#include <limits.h>
#include <stddef.h>

void bad() {
  int x = 34;
  int *pointer = &x;
  int *ref = pointer - &x;
  long int value = *ref; /* Dereferencing happens here */
}

int main() {
  bad();
}
