obj-m := phantasm.o
CC := gcc
CFLAGS := -Wall -shared -fPIC
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
DEBUG_FLAGS := -DDEBUG=1
PYTHON = python3

USERLAND_DIR := userland
USERLAND_SRC := $(wildcard $(USERLAND_DIR)/*.c)
USERLAND_OBJ := $(USERLAND_DIR)/phantasm.so

SCRIPT_DIR := scripts
PYTHON_SCRIPT := $(SCRIPT_DIR)/convert.py
HEADER_NAME := payload.h
ARRAY_NAME := phantasm_so

all: userland generate_header kernel_module

debug: CFLAGS += $(DEBUG_FLAGS)
debug: userland generate_header kernel_module

userland: $(USERLAND_OBJ)

$(USERLAND_OBJ): $(USERLAND_SRC)
	$(CC) $(CFLAGS) $^ -o $@

generate_header: $(USERLAND_OBJ)
	$(PYTHON) $(PYTHON_SCRIPT) $(USERLAND_OBJ) $(HEADER_NAME) $(ARRAY_NAME)

kernel_module: generate_header
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	rm -f $(USERLAND_OBJ)
	rm -f $(HEADER_NAME)
	$(MAKE) -C $(KDIR) M=$(PWD) clean
