#include <stdio.h>

int div (int x){
  int res, z;
  if (x >= 5)
    z = x - 5;
  else
    z = x + 2;
  res = 1000 / z;
  return res;
}

void read_file(char *file_path, char *buffer) {
  FILE *fp = fopen(file_path, "r");
  fread(buffer, sizeof(int), 1, fp);
  fclose(fp);
}

int main(int argc, char *argv[]) {
  int res, y;
  char buffer[10];
  read_file(argv[1], buffer);
  int x = buffer[0] - 65;
  printf("%d\n", x);
  y = x - 1;
  res = div(y);
  return 0;
}









