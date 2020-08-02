#ifdef CONCURRENT
#  error "CONCURRENT is defined!"
#endif
#include "allocator.h"
// #include "karmalloc.c"

PAddr PADDR_NULL = { 0, 0 };

#ifdef ALLOCTIME
struct timespec myalloc_start_time = {0, 0};
struct timespec myalloc_finish_time = {0, 0};
long long allocate_time = 0;
long long persist_time = 0;
#endif

// This struct might not be needed for simple allocator because FreeNode is used for TLAB.
typedef struct FreeNode {
    struct FreeNode *next;
    void *node;
} FreeNode;

typedef struct MemoryRoot {
    unsigned char global_lock;
    void *global_free_area_head;
    // size_t remaining_amount; // mostly unused
    // FreeNode *global_free_list_head; // for after recovery
    // unsigned char **list_lock;
    // FreeNode ***local_free_list_head_ary; // [i][j] -> スレッドiの持つスレッドj用のフリーリストへのポインタ
    // FreeNode ***local_free_list_tail_ary; // [i][j] -> スレッドiの持つスレッドj用のフリーリスト末尾へのポインタ
} MemoryRoot;

void *_pmem_mmap_head = NULL;
void *_pmem_user_head = NULL;
size_t _pmem_mmap_size = 0;  // maximum size of mmap
size_t _pmem_user_size = 0;
int _number_of_thread = 1;  // Since this code is for simgle thread
MemoryRoot *_pmem_memory_root = NULL;
size_t _tree_node_size = 0;
unsigned char _initialized_by_others = 0;


// for karmalloc
typedef double ALIGN;

union Pheader {
    struct {
        union Pheader *ptr; // pointer of next block
        unsigned size;     // size program can use
    } s;
    ALIGN x;
};

typedef union Pheader PMemHeader;

// PMemHeader base;
PMemHeader *allocp;

#define NULL 0
#define NALLOC 128


int initAllocator(void *existing_p, const char *path, size_t pmem_size, unsigned char thread_num) {
    if (existing_p != NULL) {
        _initialized_by_others = 1;
        _pmem_mmap_head = existing_p;
        _pmem_mmap_size = pmem_size;
        _pmem_user_head = _pmem_mmap_head + sizeof(AllocatorHeader);
        _pmem_user_size = pmem_size - sizeof(AllocatorHeader);
        memset(_pmem_mmap_head, 0, _pmem_mmap_size); // initialize all memory by 0
        *(PAddr *)_pmem_mmap_head = PADDR_NULL;
        return 0;
    }

    struct stat fi;
    int err;
    int fd = open(path, O_RDWR);

    // checking file descriptor
    if (fd == -1) {
        // fd error
        return -1;
    }

    // extending file
    if (fstat(fd, &fi) == -1) {
        // extending error
        perror("fstat extending error");
        return -1;
    }

    // memory mapping
    _pmem_mmap_head = mmap(NULL, pmem_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (_pmem_mmap_head == MAP_FAILED) {
        perror("failed mmap");
        return -1;
    }
    _pmem_mmap_size = pmem_size;
    _pmem_user_head = _pmem_mmap_head + sizeof(AllocatorHeader);
    _pmem_user_size = pmem_size - sizeof(AllocatorHeader);
    memset(_pmem_mmap_head, 0, _pmem_mmap_size); // initializing mmap area by 0

    // karmalloc
    PMemHeader base;
    *(PMemHeader*)_pmem_user_head = base;
    base.s.ptr = &base;
    base.s.size = _pmem_user_size - sizeof(PMemHeader);

    
    
    

    // fd can be closed after mmap
    err = close(fd);
    if (err == -1) {
        perror("close");
        return -1;
    }

    return 0;  
}

void initMemoryRoot(MemoryRoot *mr, unsigned char thread_num, void *head, size_t pmem_size, size_t node_size, FreeNode *global_list_head) {
    mr->global_lock = 0;
    mr->global_free_area_head = head;
}

void destroyMemoryRoot(MemoryRoot *mr) {
    return 0;
}

ppointer recoverAllocator(ppointer (*getNext)(ppointer)) {
    // TODO: implement recovery
    //       you may need getHeadPPointer()
}

ppointer getPersistentAddr(void *addr) {
    ppointer paddr;
    if (addr == NULL) {
        return PADDR_NULL;
    } else {
        paddr.fid = 1;
        paddr.offset = addr - _pmem_mmap_head;
        return paddr;
    }
}



int destroyAllocator() { return 0; }
ppointer recoverAllocator(ppointer (*getNext)(ppointer)) { return NULL; }

void *vol_mem_allocate(size_t size) {
    return malloc(size);
}





ppointer pst_mem_allocate(size_t size) {
    // todo: call karmalloc()
    //       persistent memory no root ni tsuite kiku
    //       enable data types other than long[int]
    // return karmalloc(size);
    void *new_node;

    new_node = karmalloc(size);


    return getPersistentAddr(new_node);
    
}




ppointer *root_allocate(size_t size, size_t node_size) {
    _pmem_memory_root = (MemoryRoot *) vol_mem_allocate(sizeof(MemoryRoot));
    initMemoryRoot(_pmem_memory_root, _number_of_thread, _pmem_user_head + size, _pmem_user_size - size, node_size, NULL);
    _tree_node_size = node_size;
    ppointer *root_p = (ppointer *) _pmem_user_head;
    if (comparePAddr(PADDR_NULL, ((AllocatorHeader*)_pmem_mmap_head)->node_head)) {
        ((AllocatorHeader *)_pmem_mmap_head)->node_head = getPersistentAddr(_pmem_user_head);
    }
    return root_p;
}

void vol_mem_free(void *p) {
    free(p);
}
void pst_mem_free(ppointer p, unsigned char node_tid, unsigned char tid) {
    free(p);
}
void root_free(ppointer *p) {
    free(p);
}

ppointer getPersistentAddr(void *p) {return p;}
void *getTransientAddr(ppointer p) {return p;}


void* karmalloc(size_t nbytes) {
    PMemHeader *p, *q;
    unsigned nunits;

    nunits = (nbytes + sizeof(PMemHeader) - 1) / sizeof(PMemHeader) + 1;  // number of block this function looking for
    if ((q=allocp) == NULL) {
        // initialization
        base.s.ptr = allocp = q = &base;
        base.s.size = 0;
    }
    for (p = q->s.ptr;; q=p, p->s.ptr) {
        if (p->s.size >= nunits) {
            if (p->s.size == nunits) {
                // exactly
                q->s.ptr = p->s.ptr;
            } else {
                p->s.size -= nunits;
                p += p->s.size;
                p->s.size = nunits;
            }
            allocp = q;
            return ((char*)(p+1)); // return only data part (without header)
        }
        if (p == allocp && (p = morecore (nunits)) == NULL) {
            // when p returns to start block (in case there is not block which has enough memory)
            // TODO: implement morecore
            return (NULL);
        }

    }
}

void free(void *ap) {
	PMemHeader *p, *q;

	p = (PMemHeader *) ap - 1;
	for (q = allocp; !(p > q && p < q->s.ptr); q = q->s.ptr)
		if (q >= q->s.ptr && (p > q || p < q->s.ptr))
			break;

	if (p + p->s.size == q->s.ptr) {
		p->s.size += q->s.ptr->s.size;
		p->s.ptr = q->s.ptr->s.ptr;
	} else
		p->s.ptr = q->s.ptr;
	if (q + q->s.size == p) {
		q->s.size += p->s.size;
		q->s.ptr = p->s.ptr;
	} else
		q->s.ptr = p;
	allocp = q;
}

static PMemHeader *morecore(u_int32_t nu)
{
	char *cp;
	PMemHeader *up;
	int rnu;

	rnu = NALLOC * ((nu + NALLOC - 1) / NALLOC);
	cp = sbrk (rnu * sizeof (PMemHeader));
	if ((long)cp == NULL)
		return (NULL);
	up = (PMemHeader *) cp;
	up->s.size = rnu;
	free ((char *)(up + 1));
	return (allocp);
}