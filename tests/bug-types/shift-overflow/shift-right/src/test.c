#include <limits.h>
#include <stdint.h>
void bad() {
  int z = 0xf5397db1;
  int x = -4;
  long res;
  res = z >> x;
  return ;
}

int main() {
  bad();
}
