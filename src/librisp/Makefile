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

install: librisp.a librisp.h
	cp librisp.h /usr/include/
	cp librisp.a /usr/lib/
	@-test ! -e /usr/include/risp.h && ln -s /usr/include/librisp.h /usr/include/risp.h
	@echo "Install complete."

clean:
	@-[ -e librisp.o ] && rm librisp.o
	@-[ -e librisp.a ] && rm librisp.a
