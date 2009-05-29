all: rfxd rfx-get

ARGS=-Wall -O2

rfxd: rfxd.c bufadd.o bufadd.h daemon.c daemon.h
	gcc -o $@ rfxd.c bufadd.o daemon.c -lrisp -levent -lexpbuf $(ARGS)



rfx-get: rfx-get.o bufadd.o rfx-common.o
	gcc -o $@ rfx-get.o bufadd.o rfx-common.o -lrisp -levent -lexpbuf

rfx-get.o: rfx-get.c bufadd.h rfx-common.h
	gcc -c -o $@ rfx-get.c $(ARGS)

bufadd.o: bufadd.c bufadd.h
	gcc -c -o $@ bufadd.c $(ARGS)

rfx-common.o: rfx-common.c rfx-common.h
	gcc -c -o $@ rfc-common.c $(ARGS)


clean:
	@-rm rfxd
	@-rm rfx-get
	@-rm *.o
