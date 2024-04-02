#include <stdio.h>
#include <setjmp.h>

float fabs_crepair(float a);
void longjmp_crepair( jmp_buf env, int status );

float fabs_crepair(float a){

  if (a > 0){
     return a;
  }
  return -a;
}

float rint_crepair(float a){

  return (int) a;
}

void longjmp_crepair( jmp_buf env, int status ){
    return;
}