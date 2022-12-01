#include <stdio.h>
struct  Struct_1 {
    short id;
    char *filepath;
    int dummy[10];
};

struct  Struct_2 {
    short id;
    char *name;
    Struct_1 *info;
};


FILE *get_pointer(char *path){
  FILE *fp = fopen(path, "r");
  return fp;
}

int main(int argc, char** argv) {
  char buffer[10];
  char **mv = argv;
  struct Struct_2 var_b;
  struct Struct_2 *ptr_b = &var_b;
  char *p = *ptr_b->info->filepath;
  FILE *fp = fopen(p, "r");
  fread(buffer, sizeof(int), 1, fp);
  fclose(fp);
  return 0;
}
