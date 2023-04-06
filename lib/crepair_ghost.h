/**
Borrowed from https://github.com/yuntongzhang/vulnfix/blob/main/lib/ghost.h
**/

int crepair_size(void *raw_addr);
int adjust_redzone_size(void* raw_addr, long adjustment);
void *crepair_base(void *raw_addr);
