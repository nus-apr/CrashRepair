#include <stdio.h>
#include <limits.h>

void bad(int x, int y) {
  int z = 4;
  z = x + y;
}


int main(int argc, char *argv[]) {
  char buffer[10];
  char *fn = argv[1];
  FILE *fp = fopen(fn, "r");
  fread(buffer, sizeof(int), 1, fp);
  fclose(fp);
  int a = buffer[0] - 65;
  int b = INT_MAX;
  bad(a, b);
  return 0;
}
