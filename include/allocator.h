#ifndef H_ALLOC
#define H_ALLOC
#  ifdef __cplusplus
extern "C" {
#  endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#ifndef NPERSIST
#  include <x86intrin.h>
#endif

#ifdef CONCURRENT
// struct PAddr {
//     unsigned int fid;
//     size_t offset;
// };

// typedef struct PAddr PAddr;

// typedef struct PAddr ppointer;
// extern ppointer PADDR_NULL;

#  define P_NULL PADDR_NULL

typedef struct AllocatorHeader {
    PAddr node_head;
    char pad[64 - sizeof(PAddr)];
} AllocatorHeader;
#else
// typedef void * ppointer;
#  define P_NULL NULL

typedef void AllocatorHeader;
#endif

struct PAddr {
    unsigned int fid;
    size_t offset;
};

typedef struct PAddr PAddr;

typedef struct PAddr ppointer;
extern ppointer PADDR_NULL;

int initAllocator(void *, const char *, size_t, unsigned char);
int destroyAllocator();
ppointer recoverAllocator(ppointer (*)(ppointer));

void *vol_mem_allocate(size_t);
ppointer pst_mem_allocate(size_t, unsigned char tid);
ppointer *root_allocate(size_t, size_t);
void vol_mem_free(void *);
void pst_mem_free(ppointer, unsigned char, unsigned char);
void root_free(ppointer *);

ppointer getPersistentAddr(void *);
void *getTransientAddr(ppointer);

#  ifdef __cplusplus
};
#  endif
#endif
