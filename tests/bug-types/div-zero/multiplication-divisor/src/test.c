#include <stdio.h>

int div (int varA, int varB){
 int div, res;
 if (varA > 5)
    varA = varA - 6;
  else
    varA = varA + 2;
  div = varA * varB;
  res = 1000 / div;
  return div;
}

void read_file(char *file_path, char *buffer) {
  FILE *fp = fopen(file_path, "r");
  fread(buffer, sizeof(int), 1, fp);
  fclose(fp);
}

int main(int argc, char *argv[]) {
  int res;
  char buffer[10];
  read_file(argv[1], buffer);
  int x = buffer[0] - 65;
  int y = buffer[1] - 65;
  printf("%d - %d\n", x, y);
  res = div(x,y);
  return 0;
}





