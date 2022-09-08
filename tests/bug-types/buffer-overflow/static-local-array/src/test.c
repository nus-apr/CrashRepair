#include <stdio.h>

void bad() {
  int array_0[] = {1234, 3436, 46353};
  int x = 56;
  int n = 3;
  int val = array_0[n];
  printf("%d\n", val);

}

int main() {
  bad();
}
