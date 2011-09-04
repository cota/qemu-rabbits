#include <stdlib.h>
#include <stdio.h>

#include "list.h"

struct memex {
    unsigned long addr;
    int cpus;
    struct list_head list;
};

LIST_HEAD(memex_list);

#define idx_to_bit(idx)	(1 << (idx))

void memex_mark(int cpu, unsigned long addr)
{
    struct memex *entry;

    addr &= 0xFFFFFFFC;

    list_for_each_entry(entry, &memex_list, list) {
        if (entry->addr == addr) {
            entry->cpus |= idx_to_bit(cpu);
            return;
        }
    }

    entry = malloc(sizeof(*entry));
    if (entry == NULL) {
        fprintf(stderr, "Error at %s: ENOMEM\n", __func__);
        exit(1);
    }
    entry->addr = addr;
    entry->cpus = idx_to_bit(cpu);
    list_add_tail(&entry->list, &memex_list);
}

int memex_test(int cpu, unsigned long addr)
{
    struct memex *entry, *tmp;

    addr &= 0xFFFFFFFC;

    list_for_each_entry_safe(entry, tmp, &memex_list, list) {
        if (entry->addr == addr) {
            if (entry->cpus & idx_to_bit(cpu)) {
                list_del(&entry->list);
                free(entry);
                return 0;
            }
            break;
        }
    }
    return 1;
}

void memex_clear(int cpu, unsigned long addr)
{
    struct memex *entry, *tmp;

    addr &= 0xFFFFFFFC;

    list_for_each_entry_safe(entry, tmp, &memex_list, list) {
        if (entry->addr == addr) {
            list_del(&entry->list);
            free(entry);
            return;
        }
    }
}
