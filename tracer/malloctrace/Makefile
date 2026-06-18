CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
TOOL_ROOTS := malloctrace

include $(CONFIG_ROOT)/makefile.config

TOOL_LDFLAGS += -Wl,-rpath,$(PIN_ROOT)/intel64/runtime/pincrt \
                -Wl,-rpath,$(PIN_ROOT)/intel64/lib \
                -Wl,-rpath,$(PIN_ROOT)/intel64/lib-ext \
                -Wl,-rpath,$(PIN_ROOT)/extras/xed-intel64/lib
				
include $(TOOLS_ROOT)/Config/makefile.default.rules

