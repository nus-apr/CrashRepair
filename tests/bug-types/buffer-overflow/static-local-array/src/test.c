#include <stdio.h>

void bad() {
  int array_0[] = {1234, 3436, 46353};
  int x = 56;
  int index = 3;
  int val = array_0[index];
  printf("%d\n", val);

}

int main() {
  bad();
}
