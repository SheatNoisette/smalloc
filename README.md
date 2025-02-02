# Smalloc

This is a simple memory allocator for C programs. It is designed to be
simple to use and to be fast. It is not designed to be thread-safe.

It is an amalgamation of the Smalloc allocator designed by Andrey Rys.

Only two files are needed to use this allocator:
- smalloc.h
- smalloc.c

Thus, this make it easy to use in any project.

Here's is the original README:
```
SMalloc -- a *static* memory allocator.

SMalloc allows you to use an arbitrary memory array, which is allocated
inside your program as, say

	static char my_memory[10240]; /* 10kb memory block */

, dynamically - that is, allocate objects of fixed length from it.

Thus, it's like you usually do:

	ptr = malloc(strlen(str)+1);
	if (!ptr) { ... error handling ... }
	... do something with ptr ...
	free(ptr);

, but space for "ptr" will be allocated from _your_ my_memory[].

SMalloc has more useful features rather than usual memory allocators available:

- Obviously, you can erase your static memory block at any time, for example,
  when you will need to wipe out some sensitive data out just before program termination,
- SMalloc allows you to use pools of any types: static storage,
  -or- obtained objects from host malloc / mmap / brk etc.
- SMalloc allows you to obtain clean zeroed objects,
- SMalloc allows you to request an exact size of (valid) memory block you obtained,
- SMalloc allows you to manage _multiple! memory arrays_ at same time,
- SMalloc allows you to check pointer validity before use,
- SMalloc tries to reuse the pool memory efficiently, because pool size is always fixed,
- SMalloc can recurse into itself, thus you can allocate a pool from existing pool and use
  it separately, just fill the pool structure, align it and pass it to *_pool() calls then,
- SMalloc will crash your program on unwanted memory behavior just like any other sane
  heap memory allocator, but it permits you to set your own crash handler, and you can
  report more about bad memory event (with pointers to current pool and offending pointer),
  or even completely avoid the crash or wipe out memory block / whatever you wish!
- Per pool OOM handlers allow you to grow pools if they run out of free space
  (if possible), or just report OOM condition gracefully.

SMalloc still will not permit you to do these things however:

- Automatic error handlers on "Out of memory" conditions,
- Playing nice with double free / header / memory corruptions,
- Shooting in your foot without serious wounds after.

## But why?

SMalloc is a design decision for my own long term project - access(8).
This program had a silly static memory allocator in past, which used large and small static arrays
of fixed lengths and this approach was really simple, but too memory wasteful of course.
Because super is not so large and does not do much of large memory allocations I seriously
thought about brk() style memory allocation, that is - just have a large memory pool and shift
an allocation pointer among it until it will not run out of memory of course. But large string
allocations and requirement of almost arbitrary string length handling made this idea inadequate.

Time passed, I felt a need for the allocator in my other (security) projects.
So I decided finally to sit and write one, even if it will take a month to write.
The working prototype however worked after less than two hours of coding :-)

Answering a generic "Why?" question is simple: because almost nobody did that in the past.

Current memory allocators, both supplied with your system and separate
libraries rely on these two (or more) things:
- process data segment which is enlarged with brk(),
- pages allocated with mmap when extra large allocations are requested or brk() returns -ENOMEM.
Usually if one or another fails with -ENOMEM, you have no options to recover other than to free
some existing allocations or to wait for condition to dissolve (which may or may not happen).
Worse, the -ENOMEM condition can appear to be completely unawaited, almost randomly.

The target of this library is to have a preallocated memory since the program start: if program
did started, it will have this memory already allocated and unreclaimable, always available.
The only problem was to use it as a big memory pool and allocate smaller objects from it instead
of opaque size, discontinous heap memory provided by host malloc.

SMalloc also strives to be very simple to understand for beginners who learn C language.

That's why such library should exist.

## Who may need it?

SMalloc maybe useful for you, if you need to:

- manage objects from preallocated static storage (primary target),
- organise memory management inside an embedded environment,
- embed ready to use memory allocator into your OS kernel project,
- manage multiple heaps (pools) simultaneously,
- learn how a simple memory allocator can work.

## Implementation details

SMalloc search strategy is simple pointer-size or start-length two stage search.
First stage searches for any allocated blocks.
Second stage searches for blocks beyond found free space.

SMalloc is a very simple allocator. It has no any additional protective features,
nor any speedup optimisations. It is NOT suitable for general usage, but only for small projects
which require small amounts of allocated objects and small pools.

It's header consists of three numbers:
- Real size of allocation,
- Pure user size of allocation,
- Magic "tag" value, which is a hash of current *header* address, the rsize and usize values above.
The header is written prior to user data. The "tag" is required to distinguish a genuine header
out of user data and to guarantee that user is not such lucky to forge it.
Real size indicates full block size with any header-wide overhead.
Real size does not include header size.
Pure user size is the value passed by user during allocation.
User size is usually lesser than real size.

"Block" is a memory area with header and user data.
Free memory can contain anything. The invalid header is considered as free memory during search.

Searches are done by shifting a header-wide pointer across the pool.
Allocated block is found by testing each possible header for validity.
During primary search allocated blocks are jumped over by their real size number.
If free space is found, a secondary search is started for possible end of free space
and next allocated block. If no such is found and size marker exceeded user requested size,
the free space is turned into block with header and pointer to user data is returned.
If during search an allocated block is found prior to user size is hit, then secondary search
is aborted, and primary search is resumed. Return of user data aborts primary search obviously.

SMalloc preventively crashes the whole program (by default) in these conditions:
- Header corruption (possibly by previous "too far" overwrite of user memory)
- Double free (previous allocation with erased header after normal free)
- Wild pointer (including pointer into pool, but no *valid* header was found for it)
Those three are normal "Undefined behavior" conditions as with any other normal memory
operations (both dynamic and static memory), so crash in these situations is justified and desirable.
However user can reassign fatal error handler to it's own function so crashes can be disabled.

SMalloc cannot work properly with relocated pool itself. The address of allocated objects is
encoded into header into tag field and cannot be mass reassigned easily.
There will be no support for that.

## Conclusion

I hope SMalloc will find it's way into many projects outside of the camp it was developed for.
Possible area to use it is an embedded world or other small projects like author's access(8).
It may fill the gap or remain mostly unknown, but I hope it will be less buggy in future :-)

SMalloc was written by Andrey "ElectroRys" Rys during Aug2017.
Contact: rys@lynxlynx.ru; https://gitlab.com/electrorys

## Licensing

SMalloc is MIT licensed: Copyright (c) 2017 Andrey Rys. All rights reserved.

By using it you absolutely, in sane mind, accept that this code can kill your dog,
terrorise your mom and finally shock you with 200VDC @ 10mA.
Although, obviously, it will not do that and cannot do, but just to warn you of possibility.
I do not know, maybe your embedded Arduino will fail with memory allocation and then will
turn it's brains insane and send a signal through optocoupler driver to a power MOSFET,
which will lead this power to you. Anything then can happen :-)

For full reuse conditions see COPYRIGHT file.
```
