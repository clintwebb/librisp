## make file for librisp64.

# Project specific variables.
PRODUCT=risp64
LIBVER=1.0.0
SOVER=2
DESTDIR=
WORKDIR=.

# Docker build envs.
DOCKER_BUILD_IMAGE=hypersys/librisp-build:1.0
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


MANPATH=/usr/local/man

all: $(WORKDIR)/$(LIBFILE)
package: $(WORKDIR)/$(LIBNAME)-$(LIBVER).tar.gz
docker-build: docker_build
src: $(WORKDIR)/$(LIBNAME)-src-$(LIBVER).tar.gz


# Need to be able to make 'man-pages' as well.  Not sure where to get the source for those... 

$(WORKDIR)/$(LIBNAME).o: $(SRCFILE) $(INCFILE)
	@echo "Making: $@"
	@-[ -d $(WORKDIR) ] || mkdir $(WORKDIR)
	gcc -c -fPIC $(SRCFILE) -o $@ $(ARGS)

$(WORKDIR)/$(LIBNAME).a: $(WORKDIR)/$(LIBNAME).o
	@echo "Making: $@"
	@-[ ! -d $(WORKDIR) ] && mkdir $(WORKDIR)
	@>$@
	@rm $@
	ar -r $@
	ar -r $@ $^

$(WORKDIR)/$(LIBFILE): $(WORKDIR)/$(LIBNAME).o
	@echo "Making: $@"
	@-[ -d $(WORKDIR) ] || mkdir $(WORKDIR)
	gcc -shared -Wl,-soname,$(SONAME) -o $@ $^


$(WORKDIR)/$(LIBNAME)-src-$(LIBVER).tar.gz: $(SRCFILE) $(INCFILE) Makefile
	@echo "Making: $@"
	@-[ ! -d $(WORKDIR) ] && mkdir $(WORKDIR)
	@-[ -e $@ ] && rm $@
	tar zcf $@ $^

$(WORKDIR)/$(LIBNAME)-$(LIBVER).tar.gz: $(WORKDIR)/$(LIBFILE) $(INCFILE) $(LIBNAME).o
	@echo "Making: $@"
	@-[ ! -d $(WORKDIR) ] && mkdir $(WORKDIR)
	@-[ -e $@ ] && rm $@
	tar zcf $@ $^


docker_build: $(SRCFILE) $(INCFILE)
	@echo "Making: $@"
	# $(DOCKER_RUN) pull $(DOCKER_BUILD_IMAGE)
	-$(DOCKER_RUN) kill $(DOCKER_NAME)
	-$(DOCKER_RUN) rm $(DOCKER_NAME)
	$(DOCKER_RUN) run --name=$(DOCKER_NAME) -v $(PWD):/build:ro $(DOCKER_BUILD_IMAGE) package
	$(DOCKER_RUN) cp $(DOCKER_NAME):/out/$(LIBNAME)-$(LIBVER).tar.gz .
	$(DOCKER_RUN) rm $(DOCKER_NAME)


install: $(WORKDIR)/$(LIBFILE)
	cp $(WORKDIR)/$(LIBFILE) $(LIBDIR)/
	@-test -e $(LIBDIR)/$(MAINFILE) && rm $(LIBDIR)/$(MAINFILE)
	ln -s $(LIBDIR)/$(LIBFILE) $(LIBDIR)/$(MAINFILE)



install_dev: $(INCFILE) man-pages
	cp $(INCFILE) $(INCDIR)/


man-pages: manpages/librisp64.3 manpages/risp_addbuf.3 manpages/risp_addbuf_noparam.3 manpages/risp_add_command.3 manpages/risp_init.3 manpages/risp_shutdown.3 manpages/risp.3 manpages/risp_addbuf_int.3 manpages/risp_addbuf_str.3 manpages/risp_add_invalid.3 manpages/risp_process.3
	@mkdir tmp.install
	@cp manpages/* tmp.install/
	@gzip tmp.install/*.3
	cp tmp.install/*.3.gz $(MANPATH)/man3/
	@rm tmp.install/*
	@rmdir tmp.install
	@echo "Man-pages Install complete."


uninstall:
	@-test -e $(LIBDIR)/$(LIBFILE) && rm $(LIBDIR)/$(LIBFILE)
	@-test -e $(LIBDIR)/$(MAINFILE) && rm $(LIBDIR)/$(MAINFILE)

clean:
	@-[ -e $(WORKDIR)/$(LIBNAME).o ] && rm $(WORKDIR)/$(LIBNAME).o
	@-[ -e $(WORKDIR)/$(LIBNAME).so* ] && rm $(WORKDIR)/$(LIBNAME).so*
