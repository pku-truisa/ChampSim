# Makefile for memusage-champsim
#
# Build: make (standalone, no glibc source needed)
#        make USE_GLIBC_SRC=1 (with full glibc features like SIGPROF timer)
#
CC = gcc
CFLAGS = -shared -fPIC -O2 -Wall -Wno-unused-result -D_GNU_SOURCE
LDFLAGS = -ldl
GLIBC_SRC = /usr/src/glibc/glibc-2.35

USE_GLIBC_SRC ?= 0

ifeq ($(USE_GLIBC_SRC),1)
# Option 1: Build using extracted glibc source
GLIBC_INCS = -I$(GLIBC_SRC) -I$(GLIBC_SRC)/include \
             -I$(GLIBC_SRC)/sysdeps/generic \
             -I$(GLIBC_SRC)/sysdeps/unix/sysv/linux \
             -I$(GLIBC_SRC)/sysdeps/unix \
             -I$(GLIBC_SRC)/sysdeps/x86_64 \
             -I$(GLIBC_SRC)/stdlib -I/usr/include/x86_64-linux-gnu
libmemusage-champsim.so: malloc_memusage-champsim.c
	$(CC) $(CFLAGS) $(GLIBC_INCS) -include stdint.h -o $@ $< $(LDFLAGS)
else
# Option 2: Standalone build (patches glibc internals, disables SIGPROF)
ALL_SRC = malloc_memusage-champsim.c
libmemusage-champsim.so: $(ALL_SRC) Makefile
	cp malloc_memusage-champsim.c _champ_src.c
	sed -i '/unistd_ext.h/d; /hp-timing.h/d; /machine-sp.h/d; /stackinfo.h/d' _champ_src.c
	sed -i 's/__glibc_unlikely(/__builtin_expect((/g' _champ_src.c
	sed -i 's/__glibc_likely(/__builtin_expect((/g' _champ_src.c
	sed -i 's/__thread_stack_pointer/sp_get/g' _champ_src.c
	sed -i 's/struct __timespec64/struct timespec/g' _champ_src.c
	sed -i 's/__clock_gettime64/clock_gettime/g' _champ_src.c
	sed -i 's/\bcreat64\b/my_creat/g' _champ_src.c
	sed -i 's/\bwrite_all\b/my_write/g' _champ_src.c
	{ echo '#include <stdint.h>'; echo '#include <time.h>'; \
	  echo '#include <string.h>'; echo '#include <signal.h>'; \
	  echo '#include <sys/stat.h>'; echo '#include <fcntl.h>'; \
	  echo 'static __inline__ uintptr_t sp_get(void) { return (uintptr_t)__builtin_frame_address(0); }'; \
	  echo 'static void my_write(int f, const void *b, size_t c) { while(c>0){ssize_t r=write(f,b,c);if(r<=0)return;b=(const char*)b+r;c-=(size_t)r;} }'; \
	  echo 'static int my_creat(const char *p, mode_t m) { return open(p,O_WRONLY|O_CREAT|O_TRUNC,m); }'; \
	  perl -0pe 's/if \(getenv\("MEMUSAGE_NO_TIMER"\) == NULL\).*?setitimer[^;]+;\s*\}/\/\* SIGPROF disabled \*\//s' _champ_src.c; \
	} > _champ_out.c && mv _champ_out.c _champ_src.c
	$(CC) $(CFLAGS) -o $@ _champ_src.c $(LDFLAGS)
	rm -f _champ_src.c
endif

all: libmemusage-champsim.so

memusage-champsim: memusage-champsim
	@true

.PHONY: all clean

clean:
	rm -f libmemusage-champsim.so _champ_src.c _champ_out.c

.PHONY: all clean