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

.PHONY: all clean test-no-ff test-ff test-trace-limit test-all

all: $(TEST_APP)

$(TEST_APP): test_app.c
	gcc -O0 -g -o $@ $<

# Test 1: No fast-forward — all instructions + alloc events inline
test-no-ff: $(TEST_APP) $(VERIFY)
	@echo "=== Test 1: No fast-forward ==="
	$(PIN) -t $(TRACER_SO) -o out_no_ff.trace -- $(TEST_APP)
	$(VERIFY) out_no_ff.trace
	@rm -f out_no_ff.trace

# Test 2: Fast-forward past all of test_app, then starting trace
# (-s with large value means all instructions are fast-forwarded,
#  trace should contain only baseline alloc dump + "Test completed" output instructions)
test-ff: $(TEST_APP) $(VERIFY)
	@echo "=== Test 2: Fast-forward (-s 50000) ==="
	$(PIN) -t $(TRACER_SO) -o out_ff.trace -s 50000 -- $(TEST_APP)
	$(VERIFY) out_ff.trace
	@rm -f out_ff.trace

# Test 3: Trace length limit (-t N) stops after N instructions
test-trace-limit: $(TEST_APP) $(VERIFY)
	@echo "=== Test 3: Trace length limit (-t 500) ==="
	$(PIN) -t $(TRACER_SO) -o out_limit.trace -t 500 -- $(TEST_APP)
	$(VERIFY) out_limit.trace
	@rm -f out_limit.trace

test-all: test-no-ff test-ff test-trace-limit

clean:
	rm -f $(TEST_APP) *.trace
