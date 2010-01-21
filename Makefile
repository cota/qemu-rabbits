# Makefile for QEMU.

include config-host.mak

.PHONY: all clean distclean

VPATH=$(SRC_PATH):$(SRC_PATH)/hw

BASE_CFLAGS= -O2 -g
BASE_LDFLAGS= -O2 -g

BASE_CFLAGS += $(OS_CFLAGS) $(ARCH_CFLAGS)
BASE_LDFLAGS += $(OS_LDFLAGS) $(ARCH_LDFLAGS)

CPPFLAGS += -I. -I$(SRC_PATH) -MMD -MP
CPPFLAGS += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
LIBS=
ifdef CONFIG_STATIC
BASE_LDFLAGS += -static
endif

#LIBS+=$(AIOLIBS)

all: $(TOOLS) recurse-all 
	cp arm-softmmu/*qemu-system-arm* release/

subdir-%: dyngen$(EXESUF) libqemu_common.a
	$(MAKE) -C $(subst subdir-,,$@) all

recurse-all: $(patsubst %,subdir-%, $(TARGET_DIRS))

#######################################################################
# BLOCK_OBJS is code used by both qemu system emulation and qemu-img

BLOCK_OBJS=cutils.o

######################################################################
# libqemu_common.a: Target indepedent part of system emulation. The
# long term path is to suppress *all* target specific code in case of
# system emulation, i.e. a single QEMU executable should support all
# CPUs and machines.

OBJS=$(BLOCK_OBJS)

OBJS+=irq.o

libqemu_common.a: $(OBJS)
	rm -f $@ 
	$(AR) rcs $@ $(OBJS)

QEMU_IMG_BLOCK_OBJS = $(BLOCK_OBJS)

######################################################################

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(BASE_CFLAGS) -c -o $@ $<

# dyngen host tool
dyngen$(EXESUF): dyngen.c
	$(HOST_CC) $(CFLAGS) $(CPPFLAGS) $(BASE_CFLAGS) -o $@ $^

clean:
# avoid old build problems by removing potentially incorrect old files
	rm -f config.mak config.h op-i386.h opc-i386.h gen-op-i386.h op-arm.h opc-arm.h gen-op-arm.h
	rm -f *.o *.d *.a $(TOOLS) dyngen$(EXESUF) TAGS cscope.* *.pod *~ */*~
	rm -f slirp/*.o slirp/*.d audio/*.o audio/*.d
	for d in $(TARGET_DIRS); do \
	$(MAKE) -C $$d $@ || exit 1 ; \
        done

distclean: clean
	rm -f config-host.mak config-host.h $(DOCS)
	rm -f qemu-{doc,tech}.{info,aux,cp,dvi,fn,info,ky,log,pg,toc,tp,vr}
	for d in $(TARGET_DIRS); do \
	rm -rf $$d || exit 1 ; \
        done

TAGS:
	etags *.[ch] tests/*.[ch]

cscope:
	rm -f ./cscope.*
	find . -name "*.[ch]" -print > ./cscope.files
	cscope -b

VERSION ?= $(shell cat VERSION)
FILE = qemu-$(VERSION)

ifneq ($(wildcard .depend),)
include .depend
endif

# Include automatically generated dependency files
-include $(wildcard *.d audio/*.d slirp/*.d)
