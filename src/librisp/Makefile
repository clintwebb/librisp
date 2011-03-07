## make file for librisp.


ARGS=
DESTDIR=
MAINFILE=librisp.so
LIBVER=1.0.1
LIBFILE=$(MAINFILE).$(LIBVER)
SONAME=$(MAINFILE).1
LIBDIR=$(DESTDIR)/usr/lib
INCDIR=$(DESTDIR)/usr/include

all: $(LIBFILE)


# Need to be able to make 'man-pages' as well.  Not sure where to get the source for those... 

librisp.o: librisp.c risp.h
	gcc -c -fPIC librisp.c -o $@ $(ARGS)

librisp.a: librisp.o
	@>$@
	@rm $@
	ar -r $@
	ar -r $@ $^

$(LIBFILE): librisp.o
	gcc -shared -Wl,-soname,$(SONAME) -o $@ $^
	

install: $(LIBFILE)
	cp $(LIBFILE) $(LIBDIR)/
	@-test -e $(LIBDIR)/$(MAINFILE) && rm $(LIBDIR)/$(MAINFILE)
	ln -s $(LIBDIR)/$(LIBFILE) $(LIBDIR)/$(MAINFILE)


install_dev: risp.h
	cp risp.h $(INCDIR)/

clean:
	@-[ -e librisp.o ] && rm librisp.o
	@-[ -e librisp.so* ] && rm librisp.so*
