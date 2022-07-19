#include <stdio.h>

FILE *get_pointer(char *filename, int n){
  FILE *fp = fopen(filename, "r");
  return fp;
}

int compute(unsigned p){
  int res = p;
  res = 200 / p;
  return res;
}

int main(int argc, char** argv) {
  char buffer[10];
  char* fn = argv[1];
  FILE *fp = get_pointer(fn, 2);
  fread(buffer, sizeof(int), 1, fp);
  int y = buffer[2];
  int res = 0;
  for (int i=y-60 ; i >=0 ; --i){
    unsigned  p = i - 1;
    res = compute(p);
  }
  return 0;

}
