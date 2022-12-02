#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  int x = argv[2];
  char *path = argv[1];
  char buffer[10];
  FILE *fp = fopen(path, "r");
  fread(buffer, sizeof(int), 1, fp);
  fclose(fp);
  int y = buffer[1];
  int *arr = (int *) malloc(10);
  int val;
  int *ptr = arr + x + y;
  *ptr = 12;
  printf("index %d = %d", x, val);
}

