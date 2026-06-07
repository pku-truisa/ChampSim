# End-to-end test for champsim_tracer PIN tool.
# Requires: PIN_ROOT exported, champsim_tracer.so built in ../obj-intel64/
#
# Usage:
#   make clean && make          # Build test_app + verify_trace
#   make test-no-ff             # Test 1: no fast-forward
#   make test-ff                # Test 2: with fast-forward (-s N)
#   make test-all               # Run all 3 tests

PIN             := /home/td/pin-3.31/pin
TRACER_SO       := ../../obj-intel64/champsim_tracer.so
TEST_APP        := ./test_app
VERIFY          := python3 verify_trace.py
VERIFY_THRESH   := python3 verify_trace_threshold.py

.PHONY: all clean test-no-ff test-ff test-trace-limit test-threshold-no-ff test-threshold-ff test-all

all: $(TEST_APP)

$(TEST_APP): test_app.c
	gcc -O0 -g -o $@ $<

# Test 1: No fast-forward — all instructions + alloc events inline (-k 0 = no threshold)
test-no-ff: $(TEST_APP) $(VERIFY)
	@echo "=== Test 1: No fast-forward (-k 0) ==="
	$(PIN) -t $(TRACER_SO) -o out_no_ff.trace -k 0 -- $(TEST_APP)
	$(VERIFY) out_no_ff.trace
	@rm -f out_no_ff.trace

# Test 2: Fast-forward past all of test_app, then starting trace (-k 0)
test-ff: $(TEST_APP) $(VERIFY)
	@echo "=== Test 2: Fast-forward (-s 50000, -k 0) ==="
	$(PIN) -t $(TRACER_SO) -o out_ff.trace -k 0 -s 50000 -- $(TEST_APP)
	$(VERIFY) out_ff.trace
	@rm -f out_ff.trace

# Test 3: Trace length limit (-t N) stops after N instructions (-k 0)
test-trace-limit: $(TEST_APP) $(VERIFY)
	@echo "=== Test 3: Trace length limit (-t 500, -k 0) ==="
	$(PIN) -t $(TRACER_SO) -o out_limit.trace -k 0 -t 500 -- $(TEST_APP)
	$(VERIFY) out_limit.trace
	@rm -f out_limit.trace

# Test 4: Threshold (-k 4096 default) — only mmap(8192) should pass
test-threshold-no-ff: $(TEST_APP) $(VERIFY_THRESH)
	@echo "=== Test 4: Threshold (-k 4096), no fast-forward ==="
	$(PIN) -t $(TRACER_SO) -o out_threshold.trace -k 4096 -- $(TEST_APP)
	$(VERIFY_THRESH) out_threshold.trace
	@rm -f out_threshold.trace

# Test 5: Threshold with fast-forward
test-threshold-ff: $(TEST_APP) $(VERIFY_THRESH)
	@echo "=== Test 5: Threshold (-k 4096) with fast-forward ==="
	$(PIN) -t $(TRACER_SO) -o out_threshold_ff.trace -k 4096 -s 50000 -- $(TEST_APP)
	$(VERIFY_THRESH) out_threshold_ff.trace
	@rm -f out_threshold_ff.trace

test-all: test-no-ff test-ff test-trace-limit test-threshold-no-ff test-threshold-ff

clean:
	rm -f $(TEST_APP) *.trace
