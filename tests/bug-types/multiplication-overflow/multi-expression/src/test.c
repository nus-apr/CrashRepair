#include <stdio.h>
#include <limits.h>


int multiply(int a, int b, int c){
  int res;
  res = (a*c)*(b+5);
  return res;
}

void read_file(char *file_path, char *buffer) {
  FILE *fp = fopen(file_path, "r");
  fread(buffer, sizeof(int), 1, fp);
  fclose(fp);
}

int main(int argc, char *argv[]) {
  int res;
  char buffer[10];
  read_file(argv[1], &buffer);
  int x = buffer[0];
  int y = buffer[1] + 214748364;
  int z = buffer[2];
  printf("%d\n", x);
  res = multiply(x,y,z);
  return 0;
}
