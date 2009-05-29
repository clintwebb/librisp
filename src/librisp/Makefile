## make file for librisp.

all: librisp.so.1.0.1

ARGS=

# Need to be able to make 'man-pages' as well.  Not sure where to get the source for those... 

librisp.o: librisp.c risp.h
	gcc -c -fPIC librisp.c -o $@ $(ARGS)

librisp.a: librisp.o
	@>$@
	@rm $@
	ar -r $@
	ar -r $@ $^

librisp.so.1.0.1: librisp.o
	gcc -shared -Wl,-soname,librisp.so.1 -o librisp.so.1.0.1 librisp.o
	

install: librisp.so.1.0.1 risp.h
	@-test -e /usr/include/risp.h && rm /usr/include/risp.h
	cp risp.h /usr/include/
	cp librisp.so.1.0.1 /usr/lib/
	@-test -e /usr/include/librisp.h && rm /usr/include/librisp.h
	@-test -e /usr/lib/librisp.so && rm /usr/lib/librisp.so
	ln -s /usr/lib/librisp.so.1.0.1 /usr/lib/librisp.so
	ldconfig
	@echo "Install complete."

clean:
	@-[ -e librisp.o ] && rm librisp.o
	@-[ -e librisp.so* ] && rm librisp.so*
