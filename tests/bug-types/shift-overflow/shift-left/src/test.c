#include <limits.h>

void bad() {
  int z = INT_MAX/2;
  int x = 3;
  int res;
  res = z << x;
  return ;
}

int main() {
  bad();
}
