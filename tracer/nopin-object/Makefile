CC       = gcc
CXX      = g++
CFLAGS   = -shared -fPIC
LDFLAGS  = -ldl
MIMALLOC = -I/usr/local/include/mimalloc-2.3 -L/usr/local/lib -lmimalloc -Wl,-rpath,/usr/local/lib

# Targets
.PHONY: all wrapper test verify clean distclean

all: wrapper

# ================================================================
# LD_PRELOAD trace wrapper
# ================================================================
wrapper: libobject_tracer_wrapper.so

libobject_tracer_wrapper.so: object_tracer_wrapper.cpp
	$(CXX) $(CFLAGS) -std=c++11 -o $@ $< $(LDFLAGS) -lpthread

# ================================================================
# Test programs
# ================================================================
test: test/test_malloc test/test_fortran test/test_mimalloc

test/test_malloc: test/test_malloc.cpp
	$(CXX) -o $@ $<

test/test_fortran: test/test_fortran.f90
	gfortran -o $@ $<

test/test_mimalloc: test/test_mimalloc.cpp
	$(CXX) -o $@ $< $(MIMALLOC)

test/test_analyzer: test/test_analyzer.cpp
	$(CXX) -o $@ $<

test/test_mimalloc_trace: test/test_mimalloc_trace.cpp
	$(CXX) -o $@ $< $(MIMALLOC)

# ================================================================
# Convenience: quick verification
# ================================================================
verify: wrapper test
	@echo "=== Verifying with glibc ==="
	TRACE_FILE=test/verify.bin LD_PRELOAD=./libobject_tracer_wrapper.so ./test/test_malloc
	@echo ""
	@echo "=== Verifying with mimalloc ==="
	TRACE_FILE=test/verify_mimalloc.bin LD_PRELOAD=./libobject_tracer_wrapper.so:/usr/local/lib/libmimalloc.so ./test/test_malloc
	@echo ""
	@echo "=== Fortran + glibc ==="
	TRACE_FILE=test/verify_fortran.bin LD_PRELOAD=./libobject_tracer_wrapper.so ./test/test_fortran
	@echo ""
	@echo "=== Fortran + mimalloc ==="
	TRACE_FILE=test/verify_fortran_mimi.bin LD_PRELOAD=./libobject_tracer_wrapper.so:/usr/local/lib/libmimalloc.so ./test/test_fortran

# ================================================================
# Clean
# ================================================================
clean:
	rm -f libobject_tracer_wrapper.so
	rm -f test/test_malloc test/test_fortran test/test_analyzer
	rm -f test/test_mimalloc test/test_mimalloc_trace

distclean: clean
	rm -f test/*.bin test/*.log test/*.result.log test/*.objects.log
	rm -f test/test_malloc_mimi test/test_malloc_v2 test/test_mimalloc_trace
	rm -f test/test-malloc.1.info.cfg test/test-malloc.1.info.status
	rm -f trace_wrapper.bin *.log
