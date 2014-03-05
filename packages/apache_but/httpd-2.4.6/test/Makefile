top_srcdir   = /home/hacker/HackingLabLCD/packages/apache_but/httpd-2.4.6
top_builddir = /home/hacker/HackingLabLCD/packages/apache_but/httpd-2.4.6
srcdir       = /home/hacker/HackingLabLCD/packages/apache_but/httpd-2.4.6/test
builddir     = /home/hacker/HackingLabLCD/packages/apache_but/httpd-2.4.6/test
VPATH        = /home/hacker/HackingLabLCD/packages/apache_but/httpd-2.4.6/test

# no targets: we don't want to build anything by default. if you want the
# test programs, then "make test"
TARGETS =

bin_PROGRAMS =

PROGRAM_LDADD        = $(EXTRA_LDFLAGS) $(PROGRAM_DEPENDENCIES) $(EXTRA_LIBS)
PROGRAM_DEPENDENCIES =  \
	$(top_srcdir)/srclib/apr-util/libaprutil.la \
	$(top_srcdir)/srclib/apr/libapr.la

include $(top_builddir)/build/rules.mk

test: $(bin_PROGRAMS)

# example for building a test proggie
# dbu_OBJECTS = dbu.lo
# dbu: $(dbu_OBJECTS)
#	$(LINK) $(dbu_OBJECTS) $(PROGRAM_LDADD)
