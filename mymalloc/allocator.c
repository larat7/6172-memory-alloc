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
#define BLOCK_SIZE(block) ((*(size_t*)((uint8_t*)block - SIZE_T_SIZE))

#ifndef BLOCK_SIZE
#define BLOCK_SIZE 1024
#endif

#define MAX_SIZE 26

typedef struct block_t {
  struct block_t* next; // 8 bytes
  // struct block_t* prev; // 8 bytes
  // uint32_t size; // 4 bytes
} block_t;

block_t* free_list[MAX_SIZE];

void* get_free_block(size_t size);

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

  // checks the free_list
  for (unsigned int i = 0; i < MAX_SIZE; i++){
    block_t* block = free_list[i];
    size_t block_size = BLOCK_SIZE(block);
    size_t min = 1 << (i-1);
    size_t max = 1 << i;
    while(block != NULL){
      if (block_size <= min || block_size > max){
        printf("Block is in the wrong bucket of free list.\n");
        printf("Bucket: %d, Block: %p, Size: %d\n\n", i, block, block_size);
        return -1;
      }
      block = block->next;
      block_size = BLOCK_SIZE(block);
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
  return 0;
}

size_t ceil_log(size_t size) {
	size_t expo = 3;
	while (1 << expo < size) { expo++; }
	return expo;
}

// Given an expo and a size, takes a block of size size in the free list
// and splits it in half.
// Returns the first half and adds the second half to the free list.
void * split(size_t expo, size_t size){
  void *ptr;
  void *free_block;

  ptr = free_list[expo+1]; // get block from free list
  free_list[expo+1] = free_list[expo+1]->next; // remove used block form free list
  *(size_t*)((char*)ptr - SIZE_T_SIZE) = expo; // change header

  // free other half.
  free_block = (void*) ((char *) ptr + size);
  *(size_t*)((char*)free_block - SIZE_T_SIZE) = (size_t) expo; // add header
  my_free(free_block);

  return ptr;
}


//  malloc - Allocate a block by incrementing the brk pointer.
//  Always allocate a block whose size is a multiple of the alignment.
void * my_malloc(size_t size) {
  // We allocate a little bit of extra memory so that we can store the
  // size of the block we've allocated.  Take a look at realloc to see
  // one example of a place where this can come in handy.
  int aligned_size = ALIGN(size + SIZE_T_SIZE);
  uint64_t *check = (uint64_t*) 0x7ffff42f0028;
  assert((*check & 0xFFFFFFFF) != 0x8);
  void *p = get_free_block(size);
  if (p != NULL){
		return p;
  // } else if (free_list[expo+1] != NULL){
  //   return split(expo, new_size);
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
    *(size_t*)p = (size_t) size;

    // Then, we return a pointer to the rest of the block of memory,
    // which is at least size bytes long.  We have to cast to uint8_t
    // before we try any pointer arithmetic because voids have no size
    // and so the compiler doesn't know how far to move the pointer.
    // Since a uint8_t is always one byte, adding SIZE_T_SIZE after
    // casting advances the pointer by SIZE_T_SIZE bytes.
    // assert(newptr != (void*) 0x7ffff433fe90);

    // assert((uint64_t) p != 0x7ffff42f0028);
    uint64_t *check = (uint64_t*) 0x7ffff42f0028;
    assert((*check & 0xFFFFFFFF) != 0x8);
    return (void *)((uint8_t *)p + SIZE_T_SIZE);
  }
}

// free - Freeing a block does nothing.
void my_free(void *ptr) {
  size_t size = *(size_t*)((uint8_t*)ptr - SIZE_T_SIZE);
  size_t expo = ceil_log(size);
  assert(size != 0);
  assert(expo < MAX_SIZE);

  block_t* prev = free_list[expo];
  free_list[expo] = (block_t*) ptr;
  free_list[expo]->next = prev;
  // free_list[expo]->size = size;
  // free_list[expo]->prev = NULL;

  // if (prev != NULL)
  //   prev->prev = free_list[expo];
}

void* get_free_block(size_t size){
  size_t expo = ceil_log(size);
  size_t block_size;
  block_t* block = free_list[expo];
  block_t* prev;

  if (block == NULL) {
    return NULL;
  }
  block_size = BLOCK_SIZE(block);
  // handles case where returned block is the first one
  if (block_size >= size) {
    free_list[expo] = block->next;
    return block;
  }
  // handles other cases
  prev = block;
  block = block->next;
  while (block != NULL) {
    block_size = BLOCK_SIZE(block);
    if (block_size >= size) {
      prev->next = block->next;
      return block;
    }
    prev = block;
    block = block->next;
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
  // size_t new_size = 1 << new_expo;

  // Get the size of the old block of memory.  Take a peek at my_malloc(),
  // where we stashed this in the SIZE_T_SIZE bytes directly before the
  // address we returned.  Now we can back up by that many bytes and read
  // the size.
  copy_size = *(size_t*)((uint8_t*)ptr - SIZE_T_SIZE);
  // copy_size = 1 << old_expo;

  // If the allocated block is big enough, return the pointer itself
  // and free remaining space.
  if (size <= copy_size){
    // *(size_t*)((uint8_t*)ptr - SIZE_T_SIZE) = new_expo; // changes header for new block
    // free_block = (void*) ((char*)ptr + new_size);
    // *(size_t*)((char*)free_block -SIZE_T_SIZE) = old_expo - new_expo; // create header for free block
    // my_free(free_block);

    return ptr;
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
