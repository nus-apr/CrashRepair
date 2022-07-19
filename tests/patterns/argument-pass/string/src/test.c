#include <stdio.h>

FILE *get_pointer(char *filename, int n){
  FILE *fp = fopen(filename, "r");
  return fp;
}

int main(int argc, char** argv) {
  char buffer[10];
  char* fn = argv[1];
  FILE *fp = get_pointer(fn, 2);
  fread(buffer, sizeof(int), 1, fp);
  int y = buffer[2] - 65;
  int res = 2;
  res = 200 / (y);
  return 0;

}
