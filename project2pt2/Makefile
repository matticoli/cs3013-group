obj-m := phase2module.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
KBUILD_CFLAGS += -w

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
