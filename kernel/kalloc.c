// Physical memory allocator, for user processes,
// kernel stacks, page-table pages,
// and pipe buffers. Allocates whole 4096-byte pages.

#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "riscv.h"
#include "defs.h"

void freerange(void *pa_start, void *pa_end, int cpu_id);

extern char end[]; // first address after kernel.
                   // defined by kernel.ld.

struct run
{
  struct run *next;
};

struct kmem
{
  struct spinlock lock;
  struct run *freelist;
};

struct
{
  struct kmem kmeml[NCPU];
} mtable;

void kinit()
{
  uint64 pa_start = PGROUNDUP((uint64)end);
  for (int cpu = 0; cpu < NCPU; cpu++)
  {
    // divide physical memory among cpus
    uint64 chunk = (PHYSTOP - pa_start) / (NCPU - cpu); // remaining division
    uint64 pa_end = PGROUNDUP(pa_start + chunk);
    initlock(&mtable.kmeml[cpu].lock, "kmem");
    mtable.kmeml[cpu].freelist = 0;
    freerange((void *)pa_start, (void *)pa_end, cpu);
    pa_start = pa_end;
  }
}

void freerange(void *pa_start, void *pa_end, int cpu_id)
{
  char *p;
  p = (char *)PGROUNDUP((uint64)pa_start);
  struct kmem *kmem = &mtable.kmeml[cpu_id]; // <-- pointer, not copy
  for (; p + PGSIZE <= (char *)pa_end; p += PGSIZE)
  {
    memset(p, 1, PGSIZE);
    struct run *r = (struct run *)p;
    acquire(&kmem->lock);
    r->next = kmem->freelist;
    kmem->freelist = r;
    release(&kmem->lock);
  }
}

void kfree(void *pa)
{
  struct run *r;

  if (((uint64)pa % PGSIZE) != 0 || (char *)pa < end || (uint64)pa >= PHYSTOP)
    panic("kfree");

  // Fill with junk to catch dangling refs.
  memset(pa, 1, PGSIZE);

  r = (struct run *)pa;
  int cpu_id = cpuid();
  struct kmem *kmem = &mtable.kmeml[cpu_id]; // <-- pointer
  acquire(&kmem->lock);
  r->next = kmem->freelist;
  kmem->freelist = r;
  release(&kmem->lock);
}

void *kalloc(void)
{
  struct run *r;
  int cpu_id = cpuid();
  struct kmem *kmem = &mtable.kmeml[cpu_id]; // <-- pointer
  acquire(&kmem->lock);
  r = kmem->freelist;
  if (r)
    kmem->freelist = r->next;
  release(&kmem->lock);

  if (!r)
  {
    // Try to steal a page from other CPUs
    for (int i = 1; i < NCPU; i++)
    {
      int other_cpu = (cpu_id + i) % NCPU;
      struct kmem *other_kmem = &mtable.kmeml[other_cpu];
      acquire(&other_kmem->lock);
      r = other_kmem->freelist;
      if (r)
      {
        other_kmem->freelist = r->next;
        release(&other_kmem->lock);
        memset((char *)r, 5, PGSIZE);
        return (void *)r; // return stolen page
      }
      release(&other_kmem->lock);
    }
  }

  if (r)
  {
    memset((char *)r, 5, PGSIZE);
  }
  return (void *)r;
}
