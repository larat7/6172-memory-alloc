/**
 * Copyright (c) 2015 MIT License by 6.172 Staff
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 **/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "./allocator_interface.h"
#include "./memlib.h"

// Don't call libc malloc!
#define malloc(...) (USE_MY_MALLOC)
#define free(...) (USE_MY_FREE)
#define realloc(...) (USE_MY_REALLOC)

// All blocks must have a specified minimum alignment.
// The alignment requirement (from config.h) is >= 8 bytes.
#ifndef ALIGNMENT
#define ALIGNMENT 8
#endif

// Rounds up to the nearest multiple of ALIGNMENT.
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

// The smallest aligned size that will hold a size_t value.
// #define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

// Size that will hold a uint32_t value (for storing the headers and footers)
#define UINT32_T_SIZE (sizeof(uint32_t))

/****
* Brief Design Overview:
* Each "block" in memory has a 4 byte header and footer at the beginning
* and end of the block that holds the size of the block. The headers and
* footers are used to easily traverse the blocks in memory.
* Since sizes are rounded to their nearest multiple of 8 to be aligned,
* we use the last bit of the header to indicate whether a block is free.
*
* A doubly linked free list is used to track the free blocks in memory
* and is used in both my_free and my_malloc.
*/

// Gets the pointer to a header for a block.
#define BLOCK_HEADER(block) ((uint32_t*)((uint8_t*)block - UINT32_T_SIZE))

// Gets whether a particular block is free.
#define IS_FREE(block) ((*BLOCK_HEADER(block)) % 2)

// Gets the size of a particular block.
#define BLOCK_SIZE(block) ((uint32_t) (*BLOCK_HEADER(block) - IS_FREE(block)))

// Gets the pointer to the footer of a block.
#define BLOCK_FOOTER(block) ((uint32_t*)((uint8_t*)block + BLOCK_SIZE(block)))

// Gets the pointer to the next block from a particular block.
#define NEXT_BLOCK(block) ((block_t*) ((uint8_t*)block + BLOCK_SIZE(block) + 2*UINT32_T_SIZE))

// Gets the size of the previous block.
#define PREVIOUS_BLOCK_SIZE(block) (*(uint32_t*)((uint8_t*)block - 2*UINT32_T_SIZE))

// Gets a pointer to the previous block.
#define PREVIOUS_BLOCK(block) ((block_t*) ((uint8_t*)block - 2*UINT32_T_SIZE - PREVIOUS_BLOCK_SIZE(block)))

// Gets the size of the last block currently allocated in memory.
#define LAST_BLOCK_SIZE *(uint32_t*)((uint8_t*)mem_heap_hi() + 1 - UINT32_T_SIZE)

// Gets the pointer to the last block in memory.
#define LAST_BLOCK ((block_t*) ((uint8_t*)mem_heap_hi()+1 - LAST_BLOCK_SIZE - UINT32_T_SIZE))

// Defines the size of the smallest block allocated.
#ifndef MIN_BLOCK_SIZE
#define MIN_BLOCK_SIZE 16
#endif

// Defines the minimum size under which a split will happen.
#ifndef MIN_SPLIT_SIZE
#define MIN_SPLIT_SIZE 256
#endif

// Defines the log of the maximum size of an allocated block.
#define MAX_SIZE 32

// Struct for a free block. Has a pointer to the next and previous free block.
typedef struct block_t {
  struct block_t* next; // 8 bytes
  struct block_t* prev; // 8 bytes
} block_t;

// Free list is an array of doubly linked lists.
// Each index holds blocks of size 2^(i - 1)+1 to 2^i
block_t* free_list[MAX_SIZE];

// Gets a block in the free list that will fit a block of size
// 'size'. Returns NULL if no such block exists.
void* get_free_block(size_t size);

// Coalesces free blocks that are adjacent to each other in memory
// together into one bigger free block.
void* coalesce(void *block);

// An internal checker - This checks our invariant that the uint32_t size header before every
// block points to either the beginning of the next block, or the end of the
// heap.
// Also checks that all the elements of the free lists are in the right bucket,
// and are in fact free. (last bit of header is 1).
int my_check() {
  char *p;
  char *lo = (char*)mem_heap_lo();
  char *hi = (char*)mem_heap_hi() + 1;
  uint32_t size = 0;

  p = lo + 4;
  while (lo <= p && p < hi) {
    size = *(uint32_t*)p - (*(uint32_t*)p % 2) + 2*UINT32_T_SIZE;
    p += size;
  }

  if (p != hi) {
    printf("Bad headers did not end at heap_hi!\n");
    printf("heap_lo: %p, heap_hi: %p, size: %d, p: %p\n", lo, hi, size, p);
    return -1;
  }

  // checks the free_list
  for (unsigned int i = 0; i < MAX_SIZE; i++){
    block_t* block = free_list[i];
    uint32_t block_size;
    uint32_t min = 1 << (i-1);
    uint32_t max = 1 << i;
    while(block != NULL){
      block_size = BLOCK_SIZE(block);
      if (block_size <= min || block_size > max){
        printf("Block is in the wrong bucket of free list.\n");
        printf("Bucket: %d, Block: %p, Size: %d\n\n", i, block, block_size);
        return -1;
      }
      if (!IS_FREE(block)){
        printf("Block is in the free list but it's not free\n");
        return -1;
      }
      block = block->next;
    }
  }

  return 0;
}

// init - Initialize the malloc package.  Called once before any other
// calls are made.  Since this is a very simple implementation, we just
// return success.
int my_init() {
  for (int i = 0; i < MAX_SIZE; i++) {
    free_list[i] = NULL;
  }
  mem_sbrk(4);
  return 0;
}

// Helper method that calculates the ceil of the log size.
size_t ceil_log(size_t size) {
	return 32 - __builtin_clz(size);
}

//  malloc - Allocate a block by incrementing the brk pointer.
//  Always allocate a block whose size is a multiple of the alignment.
void * my_malloc(size_t size) {
  // We allocate a li
  void* p;
  block_t* last_block = LAST_BLOCK;

  if (size < MIN_BLOCK_SIZE) {
    size = MIN_BLOCK_SIZE;
  }
  size = ALIGN(size); // always allocate something of a multiple of alignment.

	// As discussed above, we allocate 8 bytes of extra space (4 for the header
	// and 4 for the footer).
  int aligned_size = size + 2 * UINT32_T_SIZE;

	// Get a free block from free_lists.
  p = get_free_block(size);

	// If such a free block exists
  if (p != NULL){
    assert(IS_FREE(p));
    (*BLOCK_HEADER(p))--;
    assert(!IS_FREE(p));
    assert(BLOCK_SIZE(p) % ALIGNMENT == 0);
		return p;
	// If none exists, but the last block in the heap is free,
	// we just simply extend the heap by the difference and use
	// the freed last block.
  } else if((void*) last_block > mem_heap_lo() && IS_FREE(last_block)){
    size_t expo = ceil_log(BLOCK_SIZE(last_block));

		// removes last_block from the free list
    if (last_block->prev == NULL) {
      free_list[expo] = last_block->next;
      if (free_list[expo] != NULL) {
        free_list[expo]->prev = NULL;
      }
    } else {
      last_block->prev->next = last_block->next;
      if (last_block->next != NULL) {
        last_block->next->prev = last_block->prev;
      }
    }

		// increments heap size
    int increment_size = size - BLOCK_SIZE(last_block);
    if (increment_size > 0) {
      mem_sbrk(increment_size);
      *BLOCK_HEADER(last_block) = (uint32_t) size;
      *BLOCK_FOOTER(last_block) = (uint32_t) size;
    }

    (*BLOCK_HEADER(last_block)) -= ((*BLOCK_HEADER(last_block)) % 2);

    return (void*) last_block;
	// otherwise we just allocate more memory.
  } else {
    p = mem_sbrk(aligned_size);
  }

  if (p == (void *)-1) {
    // Whoops, an error of some sort occurred.  We return NULL to let
    // the client code know that we weren't able to allocate memory.
    return NULL;
  } else {
    // We store the size of the block we've allocated in the first
		// and last UINT32_T_SIZE bytes
    *(uint32_t*)p = (uint32_t) size; // header
    *(uint32_t*)((uint8_t*)p + aligned_size - UINT32_T_SIZE) = (uint32_t) size; // footer

    // Then, we return a pointer to the rest of the block of memory,
    // which is at least size bytes long.  We have to cast to uint8_t
    // before we try any pointer arithmetic because voids have no size
    // and so the compiler doesn't know how far to move the pointer.

    return (void *)((uint8_t *)p + UINT32_T_SIZE);
  }
}

// free - Adds a block to the appropriate linked list in free_lists.
// Attempts to coalesce (merge adjacent free lists) if possible.
void my_free(void *ptr) {
  ptr = coalesce(ptr); // attempts to coalesce
  assert(*BLOCK_HEADER(ptr) == *BLOCK_FOOTER(ptr));
  uint32_t size = BLOCK_SIZE(ptr);
  uint32_t expo = ceil_log(size);
  assert(size != 0);
  assert(expo < MAX_SIZE);

	// appends to the appropriate linked list.
  block_t* prev = free_list[expo];
  free_list[expo] = (block_t*) ptr;
  free_list[expo]->next = prev;
  free_list[expo]->prev = NULL;

  if (prev != NULL) {
    prev->prev = free_list[expo];
  }
  assert(*BLOCK_HEADER(ptr) == *BLOCK_FOOTER(ptr));
  (*BLOCK_HEADER(ptr))++;

  assert(IS_FREE(ptr));
}

// Coalesces free blocks that are adjacent to each other in memory
// together into one bigger free block.
void* coalesce(void *block){
  block_t* next_block;
  block_t* prev_block;
  uint32_t* block_header;
  uint32_t* block_footer;
  uint32_t next_block_log_size;
  uint32_t prev_block_log_size;

  uint32_t block_size = BLOCK_SIZE(block);
  uint32_t new_size;

	// if the next block is free, merge into current one.
  next_block = NEXT_BLOCK(block);
  if (IS_FREE(next_block) && (void*)next_block < mem_heap_hi()){
    next_block_log_size = ceil_log(BLOCK_SIZE(next_block));
    block_header = BLOCK_HEADER(block);
    block_footer = BLOCK_FOOTER(next_block);

    new_size = block_size + BLOCK_SIZE(next_block) + 2*UINT32_T_SIZE;
    *block_header = new_size;
    *block_footer = new_size;

		// removes next_block from the free list
    if (next_block->prev != NULL) {
      next_block->prev->next = next_block->next;
      if (next_block->next != NULL)
        next_block->next->prev = next_block->prev;
    } else {
      free_list[next_block_log_size] = next_block->next;
      if (free_list[next_block_log_size] != NULL) {
        free_list[next_block_log_size]->prev = NULL;
      }
    }

  }

	// if the previous block is free, merge into current one
  prev_block = PREVIOUS_BLOCK(block);
  if ((void*)prev_block > mem_heap_lo() && IS_FREE(prev_block)){
    prev_block_log_size = ceil_log(BLOCK_SIZE(prev_block));
    block_header = BLOCK_HEADER(prev_block);
    block_footer = BLOCK_FOOTER(block);

    new_size = BLOCK_SIZE(block) + BLOCK_SIZE(prev_block) + 2*UINT32_T_SIZE;

    *block_header = new_size;
    *block_footer = new_size;

    if (prev_block->prev != NULL) {
      prev_block->prev->next = prev_block->next;
      if (prev_block->next != NULL)
        prev_block->next->prev = prev_block->prev;
    } else {
      free_list[prev_block_log_size] = prev_block->next;
      if (free_list[prev_block_log_size] != NULL)
        free_list[prev_block_log_size]->prev = NULL;
    }

    block = prev_block;
  }

  assert(*BLOCK_HEADER(block) == *BLOCK_FOOTER(block));

  return block;
}

// Splits a block into two of specified sizes. The second one will
// be declared as free.
// The point of this is to not use more memory than needed.
// NOTE: will only split if the size of the second block is at least
// MIN_SPLIT_SIZE.
void split(block_t* block, size_t size, size_t block_size){
  block_t* prev;
  block_t* other_block = (block_t*) ((uint8_t*)block + size + 2*UINT32_T_SIZE);
  uint32_t* first_header = BLOCK_HEADER(block);
  uint32_t* second_header = BLOCK_HEADER(other_block);
  uint32_t* first_footer;
  uint32_t* second_footer;
  uint32_t expo;

  if (block_size - size >= MIN_SPLIT_SIZE){
    *first_header = size + 1;
    *second_header = block_size - size - 2*UINT32_T_SIZE;

    first_footer = BLOCK_FOOTER(block);
    second_footer = BLOCK_FOOTER(other_block);

    *first_footer = *first_header - 1;
    *second_footer = *second_header;

    // adds new block to free list
    expo = ceil_log(BLOCK_SIZE(other_block));
    prev = free_list[expo];
    free_list[expo] = other_block;
    free_list[expo]->next = prev;
    free_list[expo]->prev = NULL;

    if (prev != NULL) {
      prev->prev = free_list[expo];
    }
    assert(*BLOCK_HEADER(other_block) == *BLOCK_FOOTER(other_block));
    (*second_header)++;

    assert(IS_FREE(other_block));
  }
}

// Gets a block in the free list that will fit a block of size
// 'size', and frees the rest if necessary. Returns NULL if no such block exists.
void* get_free_block(size_t size){
  uint32_t expo = ceil_log(size);
  block_t* block = free_list[expo];

	// Gets a block from a larger bucket. (Guaranteed to fit a block of given size).
	expo = expo + 1;
	while (free_list[expo] == NULL && expo < MAX_SIZE) {
		expo++;
	}

	if (expo != MAX_SIZE) {
		block = free_list[expo];
		free_list[expo] = block->next;
		if (free_list[expo] != NULL) {
			free_list[expo]->prev = NULL;
		}
		// splits the remaining portion of the block.
		split(block, size, BLOCK_SIZE(block));
		return block;
	}
  return NULL;
}

// realloc - Implemented simply in terms of malloc and free
void * my_realloc(void *ptr, size_t size) {
  void *newptr;
  // void *free_block;
  size_t copy_size;
  // size_t old_expo;
  // size_t new_expo = ceil_log(size + SIZE_T_SIZE);
  size_t new_size;

  // Get the size of the old block of memory.  Take a peek at my_malloc(),
  // where we stashed this in the SIZE_T_SIZE bytes directly before the
  // address we returned.  Now we can back up by that many bytes and read
  // the size.
  copy_size = BLOCK_SIZE(ptr);
  // copy_size = 1 << old_expo;

  // If the allocated block is big enough, return the pointer itself
  // and free remaining space.
  if (size <= copy_size){
    return ptr;
  }

  newptr = coalesce(ptr);
  new_size = BLOCK_SIZE(newptr);

  if (size <= new_size){
    memmove(newptr, ptr, copy_size);
    // split(newptr, size, new_size);
    (*BLOCK_HEADER(newptr)) -= ((*BLOCK_HEADER(newptr)) % 2);
    assert(!IS_FREE(newptr));
    return newptr;
  }


  newptr = my_malloc(size);
  if (NULL == newptr)
    return NULL;

  // If the new block is smaller than the old one, we have to stop copying
  // early so that we don't write off the end of the new block of memory.
  // Allocate a new chunk of memory, and fail if that allocation fails.
  if (size < copy_size)
    copy_size = size;


  // This is a standard library call that performs a simple memory copy.
  memcpy(newptr, ptr, copy_size);

  // Release the old block.
  my_free(ptr);

  // Return a pointer to the new block.
  return newptr;
}

// call mem_reset_brk.
void my_reset_brk() {
  mem_reset_brk();
}

// call mem_heap_lo
void * my_heap_lo() {
  return mem_heap_lo();
}

// call mem_heap_hi
void * my_heap_hi() {
  return mem_heap_hi();
}
