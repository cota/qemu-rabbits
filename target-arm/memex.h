#ifndef __MEMEX_H__
#define __MEMEX_H__

extern int memex_test(int cpu, unsigned long addr);
extern int memex_mark(int cpu, unsigned long addr);
extern void memex_clear(int cpu, unsigned long addr);

#endif /* __MEMEX_H__ */
