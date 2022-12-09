#include <stdio.h>
#include <stdlib.h>

void func_a(int* ptr_a){
    *ptr_a = 12;
}

void func_b(int* ptr_b, int y){
    int k = y + 2;
    ptr_b += k;
    func_a(ptr_b);
}
int main(int argc, char **argv) {
  int x = argv[2];
  char *path = argv[1];
  char buffer[10];
  FILE *fp = fopen(path, "r");
  fread(buffer, sizeof(int), 1, fp);
  fclose(fp);
  int y = buffer[1];
  int *arr = (int *) malloc(10);
  func_b(arr, y);
}

