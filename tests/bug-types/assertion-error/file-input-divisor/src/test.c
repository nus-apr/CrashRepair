#include <stdio.h>
#include <assert.h>

int div (int x){
  int res, z;
  if (x >= 5){
    z = x - 5;
  }
  else {
    z = x + 2;
  }
  assert(z != 0);
  res = 1000 / z;
  return res;
}

void read_file(char *file_path, char *buffer) {
  FILE *fp = fopen(file_path, "r");
  fread(buffer, sizeof(int), 1, fp);
  fclose(fp);
}

int main(int argc, char *argv[]) {
  int res, a;
  char buffer[10];
  read_file(argv[1], buffer);
  int b = 0;
  b += buffer[0] - 65;
  printf("%d\n", b);
  a = b - 1;
  res = div(a);
  return 0;
}









