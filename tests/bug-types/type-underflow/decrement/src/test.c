#include <stdio.h>
#include <limits.h>


int decrement(int a){
  int res;
  res = --a;
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
  int y = INT_MIN;
  printf("%d\n", y);
  res = decrement(y);
  return 0;
}
