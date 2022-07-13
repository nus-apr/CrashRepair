#include <stdio.h>

void bad() {
  int x = 6;
  int n = 5;
  int arr[n];
  int i = 0;
  int val;
  while (i < x && arr[++i] !=0 ){
    val = arr[i];
    printf("index %d = %d", i, val);
  }
}

int main() {
  bad();
}
