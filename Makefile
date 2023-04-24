ccflags-y += -I$(PWD)/include
ccflags-y += -w
obj-m += SPE.o
PWD   := $(shell pwd)
LINUX_SRC := "/lib/modules/$(shell uname -r)/build"

all: clean SPEmod

.PHONY: SPEmod
SPEmod:
	$(MAKE) -C $(LINUX_SRC)  M=$(PWD) modules

clean:
	$(MAKE) -C $(LINUX_SRC) $(CFLAGS) M=$(PWD) clean