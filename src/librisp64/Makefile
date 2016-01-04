## make file for librisp64.

# Project specific variables.
PRODUCT=risp64
LIBVER=1.0.0
SOVER=2
DESTDIR=

# Docker build envs.
DOCKER_BUILD_IMAGE=hypersys/build:1.0
DOCKER_RUN=docker
DOCKER_NAME=librisp-build

# Additional compile args.
ARGS=

# Project derived variables.  Do not manually change these. These should be dependent on the variables already set.
LIBNAME=lib$(PRODUCT)
SRCFILE=$(LIBNAME).c
INCFILE=$(PRODUCT).h
MAINFILE=$(LIBNAME).so
LIBFILE=$(MAINFILE).$(LIBVER)
SONAME=$(MAINFILE).$(SOVER)
LIBDIR=$(DESTDIR)/usr/lib
INCDIR=$(DESTDIR)/usr/include

all: $(LIBFILE)
package: $(LIBNAME)-$(LIBVER).tar.gz
docker-build: docker_build

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


	
	
$(LIBNAME)-$(LIBVER).tar.gz: $(LIBFILE) $(INCFILE) $(LIBNAME).o
	@-[ -e $@ ] && rm $@
	tar zcf $@ $^


docker_build: $(SRCFILE) $(INCFILE)
	$(DOCKER_RUN) pull $(DOCKER_BUILD_IMAGE)
	-$(DOCKER_RUN) kill $(DOCKER_NAME)
	-$(DOCKER_RUN) rm $(DOCKER_NAME)
	$(DOCKER_RUN) run --name=$(DOCKER_NAME) -v $(PWD):/build $(DOCKER_BUILD_IMAGE) package
	$(DOCKER_RUN) cp $(DOCKER_NAME):/build/$(LIBNAME)-$(LIBVER).tar.gz .
	$(DOCKER_RUN) rm $(DOCKER_NAME)


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
	@-[ -e .docker_build.touchfile ] && rm .docker_build.touchfile
