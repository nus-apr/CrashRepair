#include <stdio.h>
#include <limits.h>


int add(int a, int b){
  int res;
  res = b + a;
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
  int x = buffer[1];
  int y = INT_MAX;
  printf("%d\n", x);
  res = add(x,y);
  return 0;
}
