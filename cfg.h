#ifndef _CFG_H_3T12E_
#define _CFG_H_3T12E_

//#define IMPLEMENT_FULL_CACHES
#define IMPLEMENT_LATE_CACHES
#define ONE_MEM_MODULE
#define GDB_ENABLED

/* cache associativity: defined in log2 (i.e. 0 for no associativity) */
#define CACHE_ASSOC	0

//assure a consistent configuration
#if defined(IMPLEMENT_FULL_CACHES) && defined(ONE_MEM_MODULE)
#undef ONE_MEM_MODULE
#endif

#if defined(IMPLEMENT_FULL_CACHES) && defined(IMPLEMENT_LATE_CACHES)
#error Configuration error: IMPLEMENT_FULL_CACHES and IMPLEMENT_LATE_CACHES are both defined!
#endif

#if defined(IMPLEMENT_FULL_CACHES) || defined(IMPLEMENT_LATE_CACHES)
#define IMPLEMENT_CACHES
#endif

#endif

