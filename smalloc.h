/*
 * SMalloc -- a *static* memory allocator.
 *
 * See README for a complete description.
 *
 * SMalloc is MIT licensed.
 * Copyright (c) 2017 Andrey Rys.
 * Written during Aug2017.
 */

#ifndef _SMALLOC_H
#define _SMALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

struct smalloc_pool;

typedef size_t (*smalloc_oom_handler)(struct smalloc_pool *, size_t);

/* describes static pool, if you're going to use multiple pools at same time */
struct smalloc_pool {
	void *pool; /* pointer to your pool */
	size_t pool_size; /* it's size. Must be aligned with sm_align_pool. */
	int do_zero; /* zero pool before use and all the new allocations from it. */
	smalloc_oom_handler oomfn; /* this will be called, if non-NULL, on OOM condition in pool */
};

/* a default one which is initialised with sm_set_default_pool. */
extern struct smalloc_pool smalloc_curr_pool;

/* undefined behavior handler is called on typical malloc UB situations */
typedef void (*smalloc_ub_handler)(struct smalloc_pool *, const void *);

void sm_set_ub_handler(smalloc_ub_handler);

int sm_align_pool(struct smalloc_pool *);
int sm_set_pool(struct smalloc_pool *, void *, size_t, int, smalloc_oom_handler);
int sm_set_default_pool(void *, size_t, int, smalloc_oom_handler);
int sm_release_pool(struct smalloc_pool *);
int sm_release_default_pool(void);

/* Use these with multiple pools which you control */

void *sm_malloc_pool(struct smalloc_pool *, size_t);
void *sm_zalloc_pool(struct smalloc_pool *, size_t);
void sm_free_pool(struct smalloc_pool *, void *);

void *sm_realloc_pool(struct smalloc_pool *, void *, size_t);
void *sm_realloc_move_pool(struct smalloc_pool *, void *, size_t);
void *sm_calloc_pool(struct smalloc_pool *, size_t, size_t);

int sm_alloc_valid_pool(struct smalloc_pool *spool, const void *p);

size_t sm_szalloc_pool(struct smalloc_pool *, const void *);
int sm_malloc_stats_pool(struct smalloc_pool *, size_t *, size_t *, size_t *, int *);

/* Use these when you use just default smalloc_curr_pool pool */

void *sm_malloc(size_t);
void *sm_zalloc(size_t); /* guarantee zero memory allocation */
void sm_free(void *);

void *sm_realloc(void *, size_t);
void *sm_realloc_move(void *, size_t);
void *sm_calloc(size_t, size_t); /* calls zalloc internally */

int sm_alloc_valid(const void *p); /* verify pointer without intentional crash */

size_t sm_szalloc(const void *); /* get size of allocation */
/*
 * get stats: total used, user used, total free, nr. of allocated blocks.
 * any of pointers maybe set to NULL, but at least one must be non NULL.
 */
int sm_malloc_stats(size_t *, size_t *, size_t *, int *);

// ----------------- smalloc_i.h -----------------
struct smalloc_hdr {
	size_t rsz; /* real allocated size with overhead (if any) */
	size_t usz; /* exact user size as reported by s_szalloc */
	uintptr_t tag; /* sum of all the above, hashed value */
};

#define HEADER_SZ (sizeof(struct smalloc_hdr))
#define MIN_POOL_SZ (HEADER_SZ*20)

#define VOID_PTR(p) ((void *)p)
#define CHAR_PTR(p) ((char *)p)
#define PTR_UINT(p) ((uintptr_t)VOID_PTR(p))
#define HEADER_PTR(p) ((struct smalloc_hdr *)p)
#define USER_TO_HEADER(p) (HEADER_PTR((CHAR_PTR(p)-HEADER_SZ)))
#define HEADER_TO_USER(p) (VOID_PTR((CHAR_PTR(p)+HEADER_SZ)))

extern smalloc_ub_handler smalloc_UB;

uintptr_t smalloc_uinthash(uintptr_t x);
uintptr_t smalloc_mktag(struct smalloc_hdr *shdr);
int smalloc_verify_pool(struct smalloc_pool *spool);
int smalloc_is_alloc(struct smalloc_pool *spool, struct smalloc_hdr *shdr);

void *sm_realloc_pool_i(struct smalloc_pool *spool, void *p, size_t n, int nomove);

#ifdef __cplusplus
}
#endif

#endif
