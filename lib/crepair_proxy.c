#include <stdio.h>

float fabs_trident(float a);

float fabs_trident(float a){

  if (a > 0){
     return a;
  }
  return -a;
}

float rint_trident(float a){

  return (int) a;
}
