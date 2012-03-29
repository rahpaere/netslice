obj-m += netslice.o

all: netslice_test
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f netslice_test

netslice_test: netslice_test.c netslice.h
	$(CC) -o $@ $^ $(LFLAGS)
