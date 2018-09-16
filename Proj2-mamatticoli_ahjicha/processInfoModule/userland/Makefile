obj-m := phase2module.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	gcc phase2test.c -w -o phase2test

run:
	make clean
	./phase2test

clean:
	rm ./phase2test
