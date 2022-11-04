#include <stdio.h>

float fabs_crepair(float a);

float fabs_crepair(float a){

  if (a > 0){
     return a;
  }
  return -a;
}

float rint_crepair(float a){

  return (int) a;
}
