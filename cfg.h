#ifndef _CFG_H_3T12E_
#define _CFG_H_3T12E_

//#define IMPLEMENT_CACHES
#define ONE_MEM_MODULE
#define GDB_ENABLED

//assure a consistent configuration
#if defined(IMPLEMENT_CACHES) && defined(ONE_MEM_MODULE)
#undef ONE_MEM_MODULE
#endif

#endif
