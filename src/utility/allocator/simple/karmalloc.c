#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef double ALIGN;

union Pheader {
    struct {
        union Pheader *ptr; // pointer of next block
        unsigned size;     // size program can use
    } s;
    ALIGN x;
};

typedef union Pheader PMemHeader;

static PMemHeader base;
static PMemHeader *allocp;

#define NULL 0
#define NALLOC 128

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