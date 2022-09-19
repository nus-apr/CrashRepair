#include <stdio.h>
#include <stdlib.h>

struct  Struct_1 {
    short id;
    char *filepath;
    int dummy[8];
};


int main() {
  int x = 11;
  struct Struct_1 var_b;
  for (int i=0; i<10; i++){
    var_b.dummy[i] = 0;
  }
  int val;
  val = var_b.dummy[x];
  printf("index %d = %d", x, val);
}

