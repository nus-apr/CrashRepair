int main(int argc, char *argv[]) {
  int x = 3;
  int y = 10;
  int z = 0;
  for (;;) {
    x--;
    z += y / x;
    if (x == 0) {
      break;
    }
  }
  return 0;
}









