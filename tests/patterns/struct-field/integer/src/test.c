#include <stdio.h>
struct  Struct_1 {
    int id;
    char *filepath;
    int dummy[10];
};


FILE *get_pointer(struct Struct_1 arg_a){
  FILE *fp = fopen(arg_a.filepath, "r");
  return fp;
}

int main(int argc, char** argv) {
  char buffer[10];
  char **mv = argv;
  struct Struct_1 var_b;
  struct Struct_1 *pointer;
  var_b.filepath = mv[1];
  var_b.id = atoi(argv[2]);
  FILE *fp = fopen(var_b.filepath, "r");
  fread(buffer, sizeof(int), 1, fp);
  fclose(fp);
  int y = buffer[2] + var_b.id;
  int res = 2;
  int x = y - 63;
  res = 200 / (x);
  return 0;
}
