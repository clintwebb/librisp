## make file for librisp.

all: librisp.a

ARGS=

# Need to be able to make 'man-pages' as well.  Not sure where to get the source for those... 

librisp.o: librisp.c librisp.h
	gcc -c -o $@ librisp.c $(ARGS)

librisp.a: librisp.o
	@>$@
	@rm $@
	ar -r $@
	ar -r $@ $^

clean:
	@-[ -e librisp.o ] && rm librisp.o
	@-[ -e librisp.a ] && rm librisp.a
