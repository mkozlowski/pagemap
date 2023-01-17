MAKEFLAGS += -rR

ifeq ("$(origin CC)", "default")
    undefine CC
endif

CC ?= $(CROSS_COMPILE)gcc

CFLAGS ?= -Wall -Werror -Os

B ?= .

$(B)/pagemap: pagemap.c Makefile
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(B)/pagemap

.PHONY: clean