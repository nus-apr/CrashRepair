#include <stdio.h>

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
  a = buffer[1];
  switch (a){
    case 78:
        if (a > 1)
            res = 100 / (b - 6);
    case 0:
        res = 0;
    default:
        printf("number is %d\n", res);
  }
  return 0;
}









