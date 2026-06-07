# Makefile for champsim_tracer unit tests
# No PIN SDK required — pure C++17 logic testing.

CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O0 -g
INC      := -I$(CURDIR)/../../..

SRCS     := test_main.cpp \
            test_trace_format.cpp \
            test_depth_counter.cpp \
            test_tracked_allocations.cpp \
            test_free_munmap_filter.cpp \
            test_fast_forward.cpp \
            test_writetoset.cpp \
            test_malloc_threshold.cpp

OBJS     := $(SRCS:.cpp=.o)
TARGET   := test_runner

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp test_types.h ../../inc/trace_instruction.h
	$(CXX) $(CXXFLAGS) $(INC) -c -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)