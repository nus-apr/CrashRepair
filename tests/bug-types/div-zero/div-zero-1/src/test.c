#include <stdio.h>

int div (int a){
  return 1000 /(a-5);
}
int main(int argc, char *argv[]) {
  int res, y;
  char buffer[10];
  char *fn = argv[1];
  FILE *fp = fopen(fn, "r");
  fread(buffer, sizeof(int), 1, fp);
  fclose(fp);
  int x = buffer[0] - 65;
  printf("%d\n", x);
  y = x - 1;
  res = div(y);
  return 0;
}
