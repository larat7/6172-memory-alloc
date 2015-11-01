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
#define BLOCK_HEADER(block) ((size_t*)((uint8_t*)block - SIZE_T_SIZE))
#define IS_FREE(block) ((*BLOCK_HEADER(block)) % 2)
#define BLOCK_SIZE(block) ((size_t) (*BLOCK_HEADER(block) - IS_FREE(block)))
#define BLOCK_FOOTER(block) ((size_t*)((uint8_t*)block + BLOCK_SIZE(block)))

#define NEXT_BLOCK(block) ((block_t*) ((uint8_t*)block + BLOCK_SIZE(block) + 2*SIZE_T_SIZE))
#define PREVIOUS_BLOCK_SIZE(block) (*(size_t*)((uint8_t*)block - 2*SIZE_T_SIZE))
#define PREVIOUS_BLOCK(block) ((block_t*) ((uint8_t*)block - 2*SIZE_T_SIZE - PREVIOUS_BLOCK_SIZE(block)))

#ifndef BLOCK_SIZE
#define BLOCK_SIZE 1024
#endif

#define MAX_SIZE 64

typedef struct block_t {
  struct block_t* next; // 8 bytes
  struct block_t* prev; // 8 bytes
  // uint32_t size; // 4 bytes
} block_t;

block_t* free_list[MAX_SIZE];

void* get_free_block(size_t size);
void* coalesce(void *block);

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
    size = *(size_t*)p - (*(size_t*)p % 2) + 2*SIZE_T_SIZE;
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
    size_t block_size;
    size_t min = 1 << (i-1);
    size_t max = 1 << i;
    while(block != NULL){
      block_size = BLOCK_SIZE(block);
      if (block_size <= min || block_size > max){
        printf("Block is in the wrong bucket of free list.\n");
        printf("Bucket: %d, Block: %p, Size: %lu\n\n", i, block, block_size);
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
  if (size < 16) {
    size = 16;
  }
  size = ALIGN(size);
  int aligned_size = size + 2*SIZE_T_SIZE;
  void *p = get_free_block(size);
  if (p != NULL){
    assert(IS_FREE(p));
    (*BLOCK_HEADER(p))--;
    assert(!IS_FREE(p));
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
    *(size_t*)((uint8_t*)p + aligned_size - SIZE_T_SIZE) = size;

    // Then, we return a pointer to the rest of the block of memory,
    // which is at least size bytes long.  We have to cast to uint8_t
    // before we try any pointer arithmetic because voids have no size
    // and so the compiler doesn't know how far to move the pointer.
    // Since a uint8_t is always one byte, adding SIZE_T_SIZE after
    // casting advances the pointer by SIZE_T_SIZE bytes.

    return (void *)((uint8_t *)p + SIZE_T_SIZE);
  }
}

// free - Freeing a block does nothing.
void my_free(void *ptr) {
  ptr = coalesce(ptr);
  assert(*BLOCK_HEADER(ptr) == *BLOCK_FOOTER(ptr));
  size_t size = BLOCK_SIZE(ptr);
  size_t expo = ceil_log(size);
  assert(size != 0);
  assert(expo < MAX_SIZE);

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

void* coalesce(void *block){
  block_t* next_block;
  block_t* prev_block;
  size_t* block_header;
  size_t* block_footer;
  size_t next_block_log_size;
  size_t prev_block_log_size;


  size_t block_size = BLOCK_SIZE(block);
  size_t new_size;

  next_block = NEXT_BLOCK(block);
  if (IS_FREE(next_block) && (void*)next_block < mem_heap_hi()){
    next_block_log_size = ceil_log(BLOCK_SIZE(next_block));
    block_header = BLOCK_HEADER(block);
    block_footer = BLOCK_FOOTER(next_block);

    new_size = block_size + BLOCK_SIZE(next_block) + 2*SIZE_T_SIZE;
    *block_header = new_size;
    *block_footer = new_size;

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

  prev_block = PREVIOUS_BLOCK(block);
  if ((void*)prev_block > mem_heap_lo() && IS_FREE(prev_block)){
    prev_block_log_size = ceil_log(BLOCK_SIZE(prev_block));
    block_header = BLOCK_HEADER(prev_block);
    block_footer = BLOCK_FOOTER(block);

    new_size = BLOCK_SIZE(block) + BLOCK_SIZE(prev_block) + 2*SIZE_T_SIZE;

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

void* get_free_block(size_t size){
  size_t expo = ceil_log(size);
  size_t block_size;
  block_t* block = free_list[expo];

  if (block == NULL) {
    return NULL;
  }
  block_size = BLOCK_SIZE(block);
  // handles case where returned block is the first one
  if (block_size >= size) {
    free_list[expo] = block->next;
    if (free_list[expo] != NULL) {
      free_list[expo]->prev = NULL;
    }
    assert(BLOCK_SIZE(block) == *BLOCK_FOOTER(block));
    return block;
  }
  // handles other cases
  block = block->next;
  while (block != NULL) {
    block_size = BLOCK_SIZE(block);
    if (block_size >= size) {
      block->prev->next = block->next;
      if (block->next != NULL) {
        block->next->prev = block->prev;
      }
      assert(IS_FREE(block));
      return block;
    }
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
  copy_size = BLOCK_SIZE(ptr);
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
