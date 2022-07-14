#include <limits.h>
#include <stddef.h>

void bad() {
  int * pointer = 0;
  int value = *pointer; /* Dereferencing happens here */
  printf("%d", value);
}

int main() {
  bad();
}
