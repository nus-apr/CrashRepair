#include <stdio.h>
#define PI 3.1415
#define circleArea(r,n) (PI*r*r/n)
#define squareArea(r,n) (r*n)
#define get_area(r,n,y) y = r==n ? squareArea(r,n)+1:circleArea(r,n)-2

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
  a = b - 6;
  get_area(b,a,res);
  printf("Res = %.2d", a);
  return 0;
}

