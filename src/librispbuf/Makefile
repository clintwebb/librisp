## make file for librispbuf.

all: librispbuf.so.1.0.2

ARGS=

# Need to be able to make 'man-pages' as well.  Not sure where to get the source for those... 

librispbuf.o: librispbuf.c rispbuf.h
	gcc -c -fPIC librispbuf.c -o $@ $(ARGS)

librispbuf.a: librispbuf.o
	@>$@
	@rm $@
	ar -r $@
	ar -r $@ $^

librispbuf.so.1.0.2: librispbuf.o
	gcc -shared -Wl,-soname,librispbuf.so.1 -o librispbuf.so.1.0.2 librispbuf.o
	

install: librispbuf.so.1.0.2 rispbuf.h
	@-test -e /usr/include/rispbuf.h && rm /usr/include/rispbuf.h
	cp rispbuf.h /usr/include/
	cp librispbuf.so.1.0.2 /usr/lib/
	@-test -e /usr/lib/librispbuf.so && rm /usr/lib/librispbuf.so
	ln -s /usr/lib/librispbuf.so.1.0.2 /usr/lib/librispbuf.so
	ldconfig
	@echo "Install complete."

clean:
	@-[ -e librispbuf.o ] && rm librispbuf.o
	@-[ -e librispbuf.so* ] && rm librispbuf.so*
