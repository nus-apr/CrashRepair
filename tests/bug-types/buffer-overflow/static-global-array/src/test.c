#include <stdio.h>

int array_0[] = {1234, 3436, 46353};
int array_1[] = {1234, 3436, 46353};
int array_2[] = {1234, 3436, 46353};

void bad() {
  int x = 56;
  int n = 5;
  int val = array_0[n];
  printf("%d\n", val);

}

int main() {
  bad();
}
