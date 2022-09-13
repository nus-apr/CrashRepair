#include <stdio.h>
struct  Struct_1 {
    int id;
    char *filepath;
    int dummy[10];
};

int divide(struct Struct_1 *arg_a){
  int res = 2;
  res = 200 / arg_a->id;
  return res;
}

FILE *get_pointer(struct Struct_1 arg_a){
  FILE *fp = fopen(arg_a.filepath, "r");
  return fp;
}

int main(int argc, char** argv) {
  char buffer[10];
  char **mv = argv;
  struct Struct_1 var_b;
  struct Struct_1 *pointer = &var_b;
  var_b.filepath = mv[1];
  int x = atoi(argv[2]);
  FILE *fp = fopen(var_b.filepath, "r");
  fread(buffer, sizeof(int), 1, fp);
  fclose(fp);
  var_b.id = buffer[2] + x - 66;
  int res = divide(&var_b);
  return 0;
}
