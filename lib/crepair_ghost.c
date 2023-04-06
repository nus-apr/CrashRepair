/**
Borrowed from https://github.com/yuntongzhang/vulnfix/blob/main/lib/ghost.c
**/

#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#define SHADOW_SCALE 3
#define SHADOW_OFFSET 0x7fff8000ULL // random number, need to change
#define MEM_GRANULARITY 64ULL
#define SHADOW_GRANULARITY (1ULL << SHADOW_SCALE)
#define SHADOW_MASK ~(MEM_GRANULARITY -1)

#define MEM_TO_SHADOW(mem) (((mem) >> SHADOW_SCALE) + (SHADOW_OFFSET))
#define SHADOW_TO_MEM(shadow) (((shadow) - SHADOW_OFFSET) << SHADOW_SCALE)

#define LOW_MEM_BEG   0x0ULL
#define LOW_MEM_END   (SHADOW_OFFSET ? SHADOW_OFFSET - 1 : 0)
#define HIGH_MEM_END  0x7fffffffffffULL
#define HIGH_MEM_BEG  (MEM_TO_SHADOW(HIGH_MEM_END) + 1)

#define HIGH_SHADOW_BEG (MEM_TO_SHADOW(HIGH_MEM_BEG))
#define HIGH_SHADOW_END (MEM_TO_SHADOW(HIGH_MEM_END))
#define LOW_SHADOW_BEG  SHADOW_OFFSET
#define LOW_SHADOW_END  (MEM_TO_SHADOW(LOW_MEM_END))

#define in_app_mem(addr) \
        ((LOW_MEM_BEG <= addr && addr <= LOW_MEM_END) || \
         (HIGH_MEM_BEG <= addr && addr <=HIGH_MEM_END))

#define in_low_shadow(addr) \
        (LOW_SHADOW_BEG <= addr && addr <= LOW_SHADOW_END)

#define in_high_shadow(addr) \
        (HIGH_SHADOW_BEG <= addr && addr <= HIGH_SHADOW_END)

#define in_shadow_mem(addr) \
        (in_low_shadow(addr) || in_high_shadow(addr))

#define TRAVERSE_THRESHOLD      10000
#define REDZONE_SIZE            16

#define  Heap_left_redzone       0xfa
#define  Freed_heap_region       0xfd
#define  Stack_left_redzone      0xf1
#define  Stack_mid_redzone       0xf2
#define  Stack_right_redzone     0xf3
#define  Stack_after_return      0xf5
#define  Stack_use_after_scope   0xf8
#define  Global_redzone          0xf9
#define  Global_init_order       0xf6
#define  Poisoned_by_user        0xf7
#define  Container_overflow      0xfc
#define  Array_cookie            0xac
#define  Intra_object_redzone    0xbb
#define  ASan_internal           0xfe
#define  Left_alloca_redzone     0xca
#define  Right_alloca_redzone    0xcb
#define  Shadow_gap              0xcc

typedef unsigned long uptr;

#if defined(__clang__) || defined (__GNUC__)
# define ATTRIBUTE_NO_SANITIZE_ADDRESS __attribute__((no_sanitize_address))
#else
# define ATTRIBUTE_NO_SANITIZE_ADDRESS
#endif


ATTRIBUTE_NO_SANITIZE_ADDRESS
static unsigned int shadow_byte_to_size(char shadow_byte)
{
  // indicates full redzone
  if (shadow_byte < 0)
    return -1;
  // indicates full access
  if (shadow_byte == 0)
    return 8;
  // 0x01 -> 0x07, indicates the accessable size
  return (unsigned int)shadow_byte;
}


/**
 * Returns size of buffer including raw_addr.
 * Note that: shadow_byte < 0  ====>  redzone
 **/
ATTRIBUTE_NO_SANITIZE_ADDRESS
int crepair_size(void *raw_addr)
{
  uptr addr = (uptr) raw_addr;
  if (!in_app_mem(addr))
    return -1; // error

  char *shadow_memory = (char *)MEM_TO_SHADOW(addr);
  if (!in_shadow_mem((uptr) shadow_memory))
    return -1; // error

  bool is_in_low_shadow = in_low_shadow((uptr) shadow_memory);
  bool is_in_high_shadow = in_high_shadow((uptr) shadow_memory);

  // first get shadow byte for current address
  char shadow_byte = *shadow_memory;

  char offset = addr & 7;
  if (shadow_byte < 0 || (shadow_byte > 0 && offset > shadow_byte))
    return -1; // the access to addr is overflowed

  unsigned int size = shadow_byte_to_size(shadow_byte);

  char *uiterator_shadow_memory = shadow_memory + 1;
  char *diterator_shadow_memory = shadow_memory - 1;

down_iterator:
  while (*diterator_shadow_memory >= 0)
  {
    size += 8;
    diterator_shadow_memory--;
    // guard on abnormal conditions
    uptr curr_read = (uptr) diterator_shadow_memory;
    if (is_in_low_shadow && curr_read < LOW_SHADOW_BEG)
      return -1;
    if (is_in_high_shadow && curr_read < HIGH_SHADOW_BEG)
      return -1;
    if ((int)(shadow_memory - diterator_shadow_memory) > TRAVERSE_THRESHOLD)
      return -1;
  }

up_iterator:
  while (*uiterator_shadow_memory >= 0)
  {
    size += shadow_byte_to_size(*uiterator_shadow_memory);
    uiterator_shadow_memory++;
    // guard on abnormal conditions
    uptr curr_read = (uptr) uiterator_shadow_memory;
    if (is_in_low_shadow && curr_read > LOW_SHADOW_END)
      return -1;
    if (is_in_high_shadow && curr_read > HIGH_SHADOW_END)
      return -1;
    if ((int)(uiterator_shadow_memory - shadow_memory) > TRAVERSE_THRESHOLD)
      return -1;
  }

ret:
  return size * (SHADOW_GRANULARITY / 8);
}


/**
 * Adjust redzone size of pointer raw_addr, effectively change
 * the buffer size of the pointer.
 *
 * `adjustment` is the size change in bytes.
 *
 * Returns the size of buffer after mutation
 **/
ATTRIBUTE_NO_SANITIZE_ADDRESS
int adjust_redzone_size(void* raw_addr, long adjustment)
{
  if (adjustment >= REDZONE_SIZE) // can't do mutations that potential reach in other objects
    return -1;

  uptr addr = (uptr) raw_addr;
  if (!in_app_mem(addr))
    return -1; // error

  char *shadow_memory = (char *)MEM_TO_SHADOW(addr);
  char *next_memory = shadow_memory + 1;
  while (*(next_memory++) >= 0)
    shadow_memory++;
  // now shadow_memory points to the last non-boundary byte
  char last_byte = *shadow_memory;
  unsigned int last_byte_size = shadow_byte_to_size(last_byte);

  /** Case (1): no need to change buffer **/
  if (adjustment == 0)
    return crepair_size(raw_addr);
  /** Case (2): enlarge buffer **/
  if (adjustment > 0)
  {
    // `8` is the biggest size that a byte can recognize as "accessible"
    unsigned int last_byte_capacity = 8 - last_byte_size;
    if (adjustment < last_byte_capacity) {
      // only need to modify value of the current last byte
      *shadow_memory = (char)(last_byte_size + adjustment);
    } else if (adjustment == last_byte_capacity) {
      // only need to make the last byte reach full capacity, which is denoted by 0x0
      *shadow_memory = 0x0;
    } else {
      *shadow_memory++ = 0x0;
      unsigned int num_full_bytes = (adjustment - last_byte_capacity) / 8;
      unsigned int excess_size = (adjustment - last_byte_capacity) % 8; // < 8
      for (unsigned i = 0; i < num_full_bytes; i++)
      {
        *shadow_memory++ = 0x0;
        // make sure we dont write into shadow memory of neighbouring objects
        if (*(shadow_memory+1) >= 0) // next byte is not redzone
          goto exit;
      }
      *shadow_memory = (char)excess_size;
    }
  }
  /** Case (3): shrink buffer **/
  else
  {
    char redzone_byte = *(shadow_memory + 1); // 0xf..
    unsigned size_to_shrink = - adjustment;
    if (size_to_shrink < last_byte_size) {
      // only need to modify value of the last byte
      *shadow_memory = (char)(last_byte_size - size_to_shrink);
    } else if (size_to_shrink == last_byte_size) {
      // only need to mark the last byte as full redzone
      *shadow_memory = redzone_byte;
    } else {
      *shadow_memory-- = redzone_byte;
      unsigned int num_full_bytes = (size_to_shrink - last_byte_size) / 8;
      unsigned int excess_size = (size_to_shrink - last_byte_size) % 8; // < 8
      for (unsigned i = 0; i < num_full_bytes; i++)
      {
        *shadow_memory-- = redzone_byte;
        if (*(shadow_memory-1) < 0) // next byte is redzone
          goto exit;
      }
      *shadow_memory = (char)(8 - excess_size);
    }
  }
exit:
  return crepair_size(raw_addr);
}


/**
 * Return the base of a buffer containing raw_addr
 **/
ATTRIBUTE_NO_SANITIZE_ADDRESS
void *crepair_base(void *raw_addr) {
  uptr addr = (uptr) raw_addr;
  if (!in_app_mem(addr))
    return NULL;

  char * shadow_memory = (char *)MEM_TO_SHADOW(addr);
  if (!in_shadow_mem((uptr) shadow_memory))
    return NULL;
  bool is_in_low_shadow = in_low_shadow((uptr) shadow_memory);
  bool is_in_high_shadow = in_high_shadow((uptr) shadow_memory);

  char shadow_byte = *shadow_memory;
  char offset = addr & 7;
  if (shadow_byte < 0 || (shadow_byte > 0 && offset > shadow_byte))
    return NULL; // the access to addr is overflowed

  // iterate the shadow value to find the first poisoned byte
  char * diterator_shadow_memory = shadow_memory - 1;

  while (*diterator_shadow_memory >= 0) {
    diterator_shadow_memory--;
    // guard on abnormal conditions
    uptr curr_read = (uptr) diterator_shadow_memory;
    if (is_in_low_shadow && curr_read < LOW_SHADOW_BEG)
      return NULL;
    if (is_in_high_shadow && curr_read < HIGH_SHADOW_BEG)
      return NULL;
    if ((int)(shadow_memory - diterator_shadow_memory) > TRAVERSE_THRESHOLD)
      return NULL;
  }

  return (void *)SHADOW_TO_MEM((uptr)(diterator_shadow_memory + 1));
}