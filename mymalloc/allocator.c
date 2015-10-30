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
#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

#ifndef BLOCK_SIZE
#define BLOCK_SIZE 1024
#endif

#define MAX_SIZE 64

typedef struct Node {
  struct Node* next;
} Node;

Node* freeList[MAX_SIZE];

// check - This checks our invariant that the size_t header before every
// block points to either the beginning of the next block, or the end of the
// heap.
int my_check() {
  char *p;
  char *lo = (char*)mem_heap_lo();
  char *hi = (char*)mem_heap_hi() + 1;
  size_t size = 0;

  p = lo;
  while (lo <= p && p < hi) {
    size = ALIGN(*(size_t*)p + SIZE_T_SIZE);
    p += size;
  }

  if (p != hi) {
    printf("Bad headers did not end at heap_hi!\n");
    printf("heap_lo: %p, heap_hi: %p, size: %lu, p: %p\n", lo, hi, size, p);
    return -1;
  }

  return 0;
}

// init - Initialize the malloc package.  Called once before any other
// calls are made.  Since this is a very simple implementation, we just
// return success.
int my_init() {
  for (int i = 0; i < MAX_SIZE; i++) {
    freeList[i] = NULL;
  }
  return 0;
}

size_t ceil_log_size(size_t size) {
	size_t expo = 3;
	while (1 << expo < size) { expo++; }
	return expo;
}

void * split(size_t expo, size_t size){
  void *p;
  void *free_block;

  p = freeList[expo+1]; // get block from free list
  freeList[expo+1] = freeList[expo+1]->next; // remove used block form free list
  p = (void *)((char*)p - SIZE_T_SIZE);
  *(size_t*)p = expo; // change header

  // add other half to appropriatte free list.
  free_block = (void*) ((char *) p + size);
  *(size_t*)free_block = (size_t) expo;
  free_block = (void*) ((char *)free_block + SIZE_T_SIZE);

  ((Node *) free_block)->next = freeList[expo];
  freeList[expo] = free_block;

  return (void*) ((char *)p + SIZE_T_SIZE);
}
//  malloc - Allocate a block by incrementing the brk pointer.
//  Always allocate a block whose size is a multiple of the alignment.
void * my_malloc(size_t size) {
  size_t new_size = size + SIZE_T_SIZE;
	size_t expo = ceil_log_size(new_size);
  new_size = 1 << expo;
  // We allocate a little bit of extra memory so that we can store the
  // size of the block we've allocated.  Take a look at realloc to see
  // one example of a place where this can come in handy.
  int aligned_size = ALIGN(new_size);

  assert(expo < MAX_SIZE);
  void *p;
  if (freeList[expo] != NULL){
    p = freeList[expo];
    freeList[expo] = freeList[expo]->next;
		return p;
  } else if (freeList[expo+1] != NULL){
    return split(expo, new_size);
  } else {
    p = mem_sbrk(aligned_size);
  }
  // Expands the heap by the given number of bytes and returns a pointer to
  // the newly-allocated area.  This is a slow call, so you will want to
  // make sure you don't wind up calling it on every malloc.
  // void *p = mem_sbrk(aligned_size);

  if (p == (void *)-1) {
    // Whoops, an error of some sort occurred.  We return NULL to let
    // the client code know that we weren't able to allocate memory.
    return NULL;
  } else {
    // We store the size of the block we've allocated in the first
    // SIZE_T_SIZE bytes.
    *(size_t*)p = (size_t) expo;

    // Then, we return a pointer to the rest of the block of memory,
    // which is at least size bytes long.  We have to cast to uint8_t
    // before we try any pointer arithmetic because voids have no size
    // and so the compiler doesn't know how far to move the pointer.
    // Since a uint8_t is always one byte, adding SIZE_T_SIZE after
    // casting advances the pointer by SIZE_T_SIZE bytes.
    // assert(newptr != (void*) 0x7ffff433fe90);
    return (void *)((char *)p + SIZE_T_SIZE);
  }
}

// free - Freeing a block does nothing.
void my_free(void *ptr) {
  // void* new_ptr = (void *)((char *) ptr - SIZE_T_SIZE);
  // size_t expo = *(size_t*)(new_ptr) & ((1 << SIZE_T_SIZE) - 1);
  size_t expo = *(size_t*)((uint8_t*)ptr - SIZE_T_SIZE);


  // size_t expo = *(size_t*)ptr & ((1 << sizeof(size_t)) - 1);
  assert(expo < MAX_SIZE);
  Node* prev = freeList[expo];
  freeList[expo] = (Node*) ptr;
  freeList[expo]->next = prev;
}

// realloc - Implemented simply in terms of malloc and free
void * my_realloc(void *ptr, size_t size) {
  void *newptr;
  size_t copy_size;


  // Get the size of the old block of memory.  Take a peek at my_malloc(),
  // where we stashed this in the SIZE_T_SIZE bytes directly before the
  // address we returned.  Now we can back up by that many bytes and read
  // the size.
  copy_size = *(size_t*)((uint8_t*)ptr - SIZE_T_SIZE);
  copy_size = 1 << copy_size;

  // if the allocated block is big enough, return the pointer itself
  if (size <= copy_size){
    return ptr;
  }

  // Allocate a new chunk of memory, and fail if that allocation fails.
  newptr = my_malloc(size);
  if (NULL == newptr)
    return NULL;

  // If the new block is smaller than the old one, we have to stop copying
  // early so that we don't write off the end of the new block of memory.
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
