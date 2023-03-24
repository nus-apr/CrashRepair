#include <limits.h>
#include <float.h>

void bad() {
  float z = FLT_MAX;
  int x = 3;
  int res;
  res = (int) z + x;
  return ;
}

int main() {
  bad();
}
