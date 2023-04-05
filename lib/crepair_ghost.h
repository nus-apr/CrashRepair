#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>


size_t __get_ptr_size(size_t ptr);
size_t __get_ptr_base(size_t ptr);

#define MEM_MAP_SIZE 5000
struct Map {
    size_t key;
    size_t value;
};
int map_counter = 0;
struct Map memory_map[MEM_MAP_SIZE];


size_t __get_ptr_size(size_t ptr){

   for (int i=0; i < map_counter; i++){

       struct Map map = memory_map[i];
       size_t base = map.key;
       size_t size = map.value;
       if (base == ptr)
           return size;

       if ( ptr > base && base + size > ptr)
          return size;
   }


}

size_t __get_ptr_base(size_t ptr) {

   for (int i=0; i < map_counter; i++){

       struct Map map = memory_map[i];
       size_t base = map.key;
       size_t size = map.value;
       if (base == ptr)
           return base;

       if ( ptr > base && base + size > ptr)
          return base;
   }

}

void update_size(size_t size, size_t ptr) {

   for (int i=0; i < map_counter; i++){

       struct Map map = memory_map[i];
       size_t base = map.key;
       size_t size = map.value;
       if (base == ptr){
             memory_map[i].value = size;
       }
       if ( ptr > base && base + size > ptr){
             memory_map[i].value = size;

	}


   }

}
