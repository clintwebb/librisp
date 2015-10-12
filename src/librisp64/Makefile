## make file for librisp64.


ARGS=
DESTDIR=
PRODUCT=risp64
LIBNAME=lib$(PRODUCT)
SRCFILE=$(LIBNAME).c
INCFILE=$(PRODUCT).h
MAINFILE=$(LIBNAME).so
LIBVER=1.0.0
LIBFILE=$(MAINFILE).$(LIBVER)
SONAME=$(MAINFILE).1
LIBDIR=$(DESTDIR)/usr/lib
INCDIR=$(DESTDIR)/usr/include

all: $(LIBFILE)


# Need to be able to make 'man-pages' as well.  Not sure where to get the source for those... 

$(LIBNAME).o: $(SRCFILE) $(INCFILE)
	gcc -c -fPIC $(SRCFILE) -o $@ $(ARGS)

$(LIBNAME).a: $(LIBNAME).o
	@>$@
	@rm $@
	ar -r $@
	ar -r $@ $^

$(LIBFILE): $(LIBNAME).o
	gcc -shared -Wl,-soname,$(SONAME) -o $@ $^
	

install: $(LIBFILE)
	cp $(LIBFILE) $(LIBDIR)/
	@-test -e $(LIBDIR)/$(MAINFILE) && rm $(LIBDIR)/$(MAINFILE)
	ln -s $(LIBDIR)/$(LIBFILE) $(LIBDIR)/$(MAINFILE)


install_dev: $(PRODUCT).h
	cp risp.h $(INCDIR)/


uninstall: 
	@-test -e $(LIBDIR)/$(LIBFILE) && rm $(LIBDIR)/$(LIBFILE)
	@-test -e $(LIBDIR)/$(MAINFILE) && rm $(LIBDIR)/$(MAINFILE)

clean:
	@-[ -e $(LIBNAME).o ] && rm $(LIBNAME).o
	@-[ -e $(LIBNAME).so* ] && rm $(LIBNAME).so*
