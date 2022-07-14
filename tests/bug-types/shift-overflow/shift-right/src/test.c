#include <limits.h>
#include <stdint.h>
void bad() {
  int z = 2;
  int x = -4;
  long res;
  res = 0xf5397db1 >> x;
  return ;
}

int main() {
  bad();
}
