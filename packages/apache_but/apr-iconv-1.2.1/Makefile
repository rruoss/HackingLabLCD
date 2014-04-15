#
# Top-level Makefile for APRICONV
#
abs_srcdir=/opt/git/HackingLabLCD/packages/apache_but/apr-iconv-1.2.1
abs_builddir=/opt/git/HackingLabLCD/packages/apache_but/apr-iconv-1.2.1


# bring in rules.mk for standard functionality
include /opt/git/HackingLabLCD/packages/apache_but/apr-iconv-1.2.1/build/rules.mk

SUBDIRS = lib ccs ces util
CLEAN_SUBDIRS = . lib ccs ces util

TARGET_LIB = libapriconv-1.la

DISTCLEAN_TARGETS = config.cache config.log config.status
EXTRACLEAN_TARGETS = configure libtool aclocal.m4

### install location
prefix=/opt/apache_but/apr-iconf-1.2.1
exec_prefix=/opt/apache_but/apr-iconf-1.2.1/bin
lib_prefix=/opt/apache_but/apr-iconf-1.2.1/lib
include_prefix=/opt/apache_but/apr-iconf-1.2.1/include/apr-1
libdir=/opt/apache_but/apr-iconf-1.2.1/lib/iconv

API_CPPFLAGS=

INSTALL = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644
MKINSTALLDIRS=$(abs_srcdir)/build/mkdir.sh

install:
	if [ ! -d $(DESTDIR)$(lib_prefix) ]; then \
	    $(MKINSTALLDIRS) $(DESTDIR)$(lib_prefix); \
	fi;
	(cd lib; $(LIBTOOL) --mode=install cp $(TARGET_LIB) $(DESTDIR)$(lib_prefix))
	if [ ! -d $(DESTDIR)$(libdir) ]; then \
	    $(MKINSTALLDIRS) $(DESTDIR)$(libdir); \
	fi; \
	(cd ccs; for i in *.la; do $(LIBTOOL) --mode=install cp $$i $(DESTDIR)$(libdir); done)
	(cd ces; for i in *.la; do $(LIBTOOL) --mode=install cp $$i $(DESTDIR)$(libdir); done)
	if [ ! -d $(DESTDIR)$(include_prefix) ]; then \
	    $(MKINSTALLDIRS) $(DESTDIR)$(include_prefix); \
	fi;
	$(INSTALL_DATA) $(abs_srcdir)/include/api_version.h $(DESTDIR)$(include_prefix)
	$(INSTALL_DATA) $(abs_srcdir)/include/apr_iconv.h $(DESTDIR)$(include_prefix)
	if [ ! -d $(DESTDIR)$(exec_prefix) ]; then \
	    $(MKINSTALLDIRS) $(DESTDIR)$(exec_prefix); \
	fi; \
	(cd util; $(LIBTOOL) --mode=install cp apriconv $(DESTDIR)$(exec_prefix))

all:
	(cd lib;  $(MAKE) CPPFLAGS="$(API_CPPFLAGS) $(CPPFLAGS)")
	(cd ccs;  $(MAKE))
	(cd ces;  $(MAKE))
	(cd util; $(MAKE))

docs:
	mkdir ./docs
	perl $(abs_srcdir)/build/scandoc.pl -i./build/default.pl -p./docs/ ./lib/*.h

.PHONY: delete-lib
