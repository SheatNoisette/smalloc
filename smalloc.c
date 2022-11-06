/*
 * This file is a part of SMalloc.
 * SMalloc is MIT licensed.
 * Copyright (c) 2017 Andrey Rys.
 */

#include "smalloc.h"

int sm_alloc_valid_pool(struct smalloc_pool *spool, const void *p)
{
	struct smalloc_hdr *shdr;

	if (!smalloc_verify_pool(spool)) {
		errno = EINVAL;
		return 0;
	}

	if (!p) return 0;

	shdr = USER_TO_HEADER(p);
	if (smalloc_is_alloc(spool, shdr)) return 1;
	return 0;
}

int sm_alloc_valid(const void *p)
{
	return sm_alloc_valid_pool(&smalloc_curr_pool, p);
}

// sm_calloc.c
void *sm_calloc_pool(struct smalloc_pool *spool, size_t x, size_t y)
{
	return sm_zalloc_pool(spool, x * y);
}

void *sm_calloc(size_t x, size_t y)
{
	return sm_calloc_pool(&smalloc_curr_pool, x, y);
}

// sm_free.c
void sm_free_pool(struct smalloc_pool *spool, void *p)
{
	struct smalloc_hdr *shdr;
	char *s;

	if (!smalloc_verify_pool(spool)) {
		errno = EINVAL;
		return;
	}

	if (!p) return;

	shdr = USER_TO_HEADER(p);
	if (smalloc_is_alloc(spool, shdr)) {
		if (spool->do_zero) memset(p, 0, shdr->rsz);
		s = CHAR_PTR(p);
		s += shdr->usz;
		memset(s, 0, HEADER_SZ);
		if (spool->do_zero) memset(s+HEADER_SZ, 0, shdr->rsz - shdr->usz);
		memset(shdr, 0, HEADER_SZ);
		return;
	}

	smalloc_UB(spool, p);
	return;
}

void sm_free(void *p)
{
	sm_free_pool(&smalloc_curr_pool, p);
}

// sm_hash.c
/* An adopted Jenkins one-at-a-time hash */
#define UIHOP(x, s) do {		\
		hash += (x >> s) & 0xff;\
		hash += hash << 10;	\
		hash ^= hash >> 6;	\
	} while (0)
uintptr_t smalloc_uinthash(uintptr_t x)
{
	uintptr_t hash = 0;

	UIHOP(x, 0);
	UIHOP(x, 8);
	UIHOP(x, 16);
	UIHOP(x, 24);

	hash += hash << 3;
	hash ^= hash >> 11;
	hash += hash << 15;

	return hash;
}
#undef UIHOP

uintptr_t smalloc_mktag(struct smalloc_hdr *shdr)
{
	uintptr_t r = smalloc_uinthash(PTR_UINT(shdr));
	r += shdr->rsz;
	r = smalloc_uinthash(r);
	r += shdr->usz;
	r = smalloc_uinthash(r);
	return r;
}

// sm_malloc_stats.c

int sm_malloc_stats_pool(struct smalloc_pool *spool, size_t *total, size_t *user, size_t *free, int *nr_blocks)
{
	struct smalloc_hdr *shdr, *basehdr;
	int r = 0;

	if (!smalloc_verify_pool(spool)) {
		errno = EINVAL;
		return -1;
	}

	if (!total && !user && !free && !nr_blocks) return 0;

	if (total) *total = 0;
	if (user) *user = 0;
	if (free) *free = 0;
	if (nr_blocks) *nr_blocks = 0;

	shdr = basehdr = (struct smalloc_hdr *)spool->pool;
	while (CHAR_PTR(shdr)-CHAR_PTR(basehdr) < spool->pool_size) {
		if (smalloc_is_alloc(spool, shdr)) {
			if (total) *total += HEADER_SZ + shdr->rsz + HEADER_SZ;
			if (user) *user += shdr->usz;
			if (nr_blocks) *nr_blocks += 1;
			r = 1;
		}

		shdr++;
	}

	*free = spool->pool_size - *total;

	return r;
}

int sm_malloc_stats(size_t *total, size_t *user, size_t *free, int *nr_blocks)
{
	return sm_malloc_stats_pool(&smalloc_curr_pool, total, user, free, nr_blocks);
}

// sm_malloc.c
void *sm_malloc_pool(struct smalloc_pool *spool, size_t n)
{
	struct smalloc_hdr *basehdr, *shdr, *dhdr;
	char *s;
	int found;
	size_t x;

again:	if (!smalloc_verify_pool(spool)) {
		errno = EINVAL;
		return NULL;
	}

	if (n == 0) n++; /* return a block successfully */
	if (n > SIZE_MAX
	|| n > (spool->pool_size - HEADER_SZ)) goto oom;

	shdr = basehdr = (struct smalloc_hdr *)spool->pool;
	while (CHAR_PTR(shdr)-CHAR_PTR(basehdr) < spool->pool_size) {
		/*
		 * Already allocated block.
		 * Skip it by jumping over it.
		 */
		if (smalloc_is_alloc(spool, shdr)) {
			s = CHAR_PTR(HEADER_TO_USER(shdr));
			s += shdr->rsz + HEADER_SZ;
			shdr = HEADER_PTR(s);
			continue;
		}
		/*
		 * Free blocks ahead!
		 * Do a second search over them to find out if they're
		 * really large enough to fit the new allocation.
		 */
		else {
			dhdr = shdr; found = 0;
			while (CHAR_PTR(dhdr)-CHAR_PTR(basehdr) < spool->pool_size) {
				/* pre calculate free block size */
				x = CHAR_PTR(dhdr)-CHAR_PTR(shdr);
				/*
				 * ugh, found next allocated block.
				 * skip this candidate then.
				 */
				if (smalloc_is_alloc(spool, dhdr))
					goto allocblock;
				/*
				 * did not see allocated block yet,
				 * but this free block is of enough size
				 * - finally, use it.
				 */
				if (n + HEADER_SZ <= x) {
					x -= HEADER_SZ;
					found = 1;
					goto outfound;
				}
				dhdr++;
			}

outfound:		if (found) {
				uintptr_t tag;
				/* allocate and return this block */
				shdr->rsz = x;
				shdr->usz = n;
				shdr->tag = tag = smalloc_mktag(shdr);
				if (spool->do_zero) memset(HEADER_TO_USER(shdr), 0, shdr->rsz);
				s = CHAR_PTR(HEADER_TO_USER(shdr));
				s += shdr->usz;
				for (x = 0;
				x < sizeof(struct smalloc_hdr);
				x += sizeof(uintptr_t)) {
					tag = smalloc_uinthash(tag);
					memcpy(s+x, &tag, sizeof(uintptr_t));
				}
				memset(s+x, 0xff, shdr->rsz - shdr->usz);
				return HEADER_TO_USER(shdr);
			}

			/* continue first search for next free block */
allocblock:		shdr = dhdr;
			continue;
		}

		shdr++;
	}

oom:	if (spool->oomfn) {
		x = spool->oomfn(spool, n);
		if (x > spool->pool_size) {
			spool->pool_size = x;
			if (sm_align_pool(spool)) goto again;
		}
	}

	errno = ENOMEM;
	return NULL;
}

void *sm_malloc(size_t n)
{
	return sm_malloc_pool(&smalloc_curr_pool, n);
}

// sm_pool.c
struct smalloc_pool smalloc_curr_pool;

int smalloc_verify_pool(struct smalloc_pool *spool)
{
	if (!spool->pool || !spool->pool_size) return 0;
	if (spool->pool_size % HEADER_SZ) return 0;
	return 1;
}

int sm_align_pool(struct smalloc_pool *spool)
{
	size_t x;

	if (smalloc_verify_pool(spool)) return 1;

	x = spool->pool_size % HEADER_SZ;
	if (x) spool->pool_size -= x;
	if (spool->pool_size <= MIN_POOL_SZ) {
		errno = ENOSPC;
		return 0;
	}

	return 1;
}

int sm_set_pool(struct smalloc_pool *spool, void *new_pool, size_t new_pool_size, int do_zero, smalloc_oom_handler oom_handler)
{
	if (!spool) {
		errno = EINVAL;
		return 0;
	}

	if (!new_pool || !new_pool_size) {
		if (smalloc_verify_pool(spool)) {
			if (spool->do_zero) memset(spool->pool, 0, spool->pool_size);
			memset(spool, 0, sizeof(struct smalloc_pool));
			return 1;
		}

		errno = EINVAL;
		return 0;
	}

	spool->pool = new_pool;
	spool->pool_size = new_pool_size;
	spool->oomfn = oom_handler;
	if (!sm_align_pool(spool)) return 0;

	if (do_zero) {
		spool->do_zero = do_zero;
		memset(spool->pool, 0, spool->pool_size);
	}

	return 1;
}

int sm_set_default_pool(void *new_pool, size_t new_pool_size, int do_zero, smalloc_oom_handler oom_handler)
{
	return sm_set_pool(&smalloc_curr_pool, new_pool, new_pool_size, do_zero, oom_handler);
}

int sm_release_pool(struct smalloc_pool *spool)
{
	return sm_set_pool(spool, NULL, 0, 0, NULL);
}

int sm_release_default_pool(void)
{
	return sm_release_pool(&smalloc_curr_pool);
}

// sm_realloc_i.c
/*
 * Please do NOT use this function directly or rely on it's presence.
 * It may go away in future SMalloc versions, or it's calling
 * signature may change. It is internal function, hence "_i" suffix.
 */
void *sm_realloc_pool_i(struct smalloc_pool *spool, void *p, size_t n, int nomove)
{
	struct smalloc_hdr *basehdr, *shdr, *dhdr;
	void *r;
	char *s;
	int found;
	size_t rsz, usz, x;
	uintptr_t tag;

	if (!smalloc_verify_pool(spool)) {
		errno = EINVAL;
		return NULL;
	}

	if (!p) return sm_malloc_pool(spool, n);
	if (!n && p) {
		sm_free_pool(spool, p);
		return NULL;
	}

	/* determine user size */
	shdr = USER_TO_HEADER(p);
	if (!smalloc_is_alloc(spool, shdr)) smalloc_UB(spool, p);
	usz = shdr->usz;
	rsz = shdr->rsz;

	/* newsize is lesser than allocated - truncate */
	if (n <= usz) {
		if (spool->do_zero) memset((char *)p + n, 0, shdr->rsz - n);
		s = CHAR_PTR(HEADER_TO_USER(shdr));
		s += usz;
		memset(s, 0, HEADER_SZ);
		if (spool->do_zero) memset(s+HEADER_SZ, 0, rsz - usz);
		shdr->rsz = (n%HEADER_SZ)?(((n/HEADER_SZ)+1)*HEADER_SZ):n;
		shdr->usz = n;
		shdr->tag = tag = smalloc_mktag(shdr);
		s = CHAR_PTR(HEADER_TO_USER(shdr));
		s += shdr->usz;
		for (x = 0; x < sizeof(struct smalloc_hdr); x += sizeof(uintptr_t)) {
			tag = smalloc_uinthash(tag);
			memcpy(s+x, &tag, sizeof(uintptr_t));
		}
		memset(s+x, 0xff, shdr->rsz - shdr->usz);
		return p;
	}

	/* newsize is bigger than allocated, but there is free room - modify */
	if (n > usz && n <= rsz) {
		if (spool->do_zero) {
			s = CHAR_PTR(HEADER_TO_USER(shdr));
			s += usz;
			memset(s, 0, HEADER_SZ);
		}
		shdr->usz = n;
		shdr->tag = tag = smalloc_mktag(shdr);
		s = CHAR_PTR(HEADER_TO_USER(shdr));
		s += shdr->usz;
		for (x = 0; x < sizeof(struct smalloc_hdr); x += sizeof(uintptr_t)) {
			tag = smalloc_uinthash(tag);
			memcpy(s+x, &tag, sizeof(uintptr_t));
		}
		memset(s+x, 0xff, shdr->rsz - shdr->usz);
		return p;
	}

	/* newsize is bigger, larger than rsz but there are free blocks beyond - extend */
	basehdr = (struct smalloc_hdr *)spool->pool; dhdr = shdr+(rsz/HEADER_SZ); found = 0;
	while (CHAR_PTR(dhdr)-CHAR_PTR(basehdr) < spool->pool_size) {
		x = CHAR_PTR(dhdr)-CHAR_PTR(shdr);
		if (smalloc_is_alloc(spool, dhdr))
			goto allocblock;
		if (n + HEADER_SZ <= x) {
			x -= HEADER_SZ;
			found = 1;
			goto outfound;
		}
		dhdr++;
	}

outfound:
	/* write new numbers of same allocation */
	if (found) {
		if (spool->do_zero) {
			s = CHAR_PTR(HEADER_TO_USER(shdr));
			s += usz;
			memset(s, 0, HEADER_SZ);
			memset(s+HEADER_SZ, 0, rsz - usz);
		}
		shdr->rsz = x;
		shdr->usz = n;
		shdr->tag = tag = smalloc_mktag(shdr);
		s = CHAR_PTR(HEADER_TO_USER(shdr));
		s += shdr->usz;
		for (x = 0; x < sizeof(struct smalloc_hdr); x += sizeof(uintptr_t)) {
			tag = smalloc_uinthash(tag);
			memcpy(s+x, &tag, sizeof(uintptr_t));
		}
		memset(s+x, 0xff, shdr->rsz - shdr->usz);
		return p;
	}

allocblock:
	/* newsize is bigger than allocated and no free space - move */
	if (nomove) {
		/* fail if user asked */
		errno = ERANGE;
		return NULL;
	}
	r = sm_malloc_pool(spool, n);
	if (!r) return NULL;
	memcpy(r, p, usz);
	sm_free_pool(spool, p);

	return r;
}

// sm_realloc_move.c
void *sm_realloc_move_pool(struct smalloc_pool *spool, void *p, size_t n)
{
	return sm_realloc_pool_i(spool, p, n, 1);
}

void *sm_realloc_move(void *p, size_t n)
{
	return sm_realloc_pool_i(&smalloc_curr_pool, p, n, 1);
}

// sm_realloc.c

void *sm_realloc_pool(struct smalloc_pool *spool, void *p, size_t n)
{
	return sm_realloc_pool_i(spool, p, n, 0);
}

void *sm_realloc(void *p, size_t n)
{
	return sm_realloc_pool_i(&smalloc_curr_pool, p, n, 0);
}

// sm_szalloc.c
size_t sm_szalloc_pool(struct smalloc_pool *spool, const void *p)
{
	struct smalloc_hdr *shdr;

	if (!smalloc_verify_pool(spool)) {
		errno = EINVAL;
		return ((size_t)-1);
	}

	if (!p) return 0;

	shdr = USER_TO_HEADER(p);
	if (smalloc_is_alloc(spool, shdr)) return shdr->usz;
	smalloc_UB(spool, p);
	return 0;
}

size_t sm_szalloc(const void *p)
{
	return sm_szalloc_pool(&smalloc_curr_pool, p);
}

// sm_util.c
static int smalloc_check_bounds(struct smalloc_pool *spool, struct smalloc_hdr *shdr)
{
	if (!spool) return 0;
	if (CHAR_PTR(shdr) >= CHAR_PTR(spool->pool)
	&& CHAR_PTR(shdr) <= (CHAR_PTR(spool->pool)+spool->pool_size))
		return 1;
	return 0;
}

static int smalloc_valid_tag(struct smalloc_hdr *shdr)
{
	char *s;
	uintptr_t r = smalloc_mktag(shdr);
	size_t x;

	if (shdr->tag == r) {
		s = CHAR_PTR(HEADER_TO_USER(shdr));
		s += shdr->usz;
		for (x = 0; x < sizeof(struct smalloc_hdr); x += sizeof(uintptr_t)) {
			r = smalloc_uinthash(r);
			if (memcmp(s+x, &r, sizeof(uintptr_t)) != 0) return 0;
		}
		s += x; x = 0;
		while (x < shdr->rsz - shdr->usz) {
			if (s[x] != '\xFF') return 0;
			x++;
		}
		return 1;
	}
	return 0;
}

static void smalloc_do_crash(struct smalloc_pool *spool, const void *p)
{
	char *c = NULL;
	*c = 'X';
}

smalloc_ub_handler smalloc_UB = smalloc_do_crash;

void sm_set_ub_handler(smalloc_ub_handler handler)
{
	if (!handler) smalloc_UB = smalloc_do_crash;
	else smalloc_UB = handler;
}

int smalloc_is_alloc(struct smalloc_pool *spool, struct smalloc_hdr *shdr)
{
	if (!smalloc_check_bounds(spool, shdr)) return 0;
	if (shdr->rsz == 0) return 0;
	if (shdr->rsz > SIZE_MAX) return 0;
	if (shdr->usz > SIZE_MAX) return 0;
	if (shdr->usz > shdr->rsz) return 0;
	if (shdr->rsz % HEADER_SZ) return 0;
	if (!smalloc_valid_tag(shdr)) return 0;
	return 1;
}

// sm_zalloc.c
void *sm_zalloc_pool(struct smalloc_pool *spool, size_t n)
{
	void *r = sm_malloc_pool(spool, n);
	if (r) memset(r, 0, n);
	return r;
}

void *sm_zalloc(size_t n)
{
	return sm_zalloc_pool(&smalloc_curr_pool, n);
}

