
INCLUDES = -I/opt/git/HackingLabLCD/packages/apache_but/apr-iconv-1.2.1/lib -I/opt/git/HackingLabLCD/packages/apache_but/apr-iconv-1.2.1/include  -I/opt/apache_but/apr-1.5.0/include/apr-1 

PROGRAMS = apriconv
TARGETS  = $(PROGRAMS)

# bring in rules.mk for standard functionality
include /opt/git/HackingLabLCD/packages/apache_but/apr-iconv-1.2.1/build/rules.mk

iconv_OBJECTS = iconv.lo iconv_stream.lo
iconv_LDADD   = ../lib/libapriconv-1.la
APR_LIBS      =  /opt/apache_but/apr-1.5.0/lib/libapr-1.la -lrt -lcrypt  -lpthread -ldl

apriconv:	$(iconv_OBJECTS) $(iconv_LDADD)
	$(LINK) -o $@ $(iconv_OBJECTS) $(iconv_LDADD) $(LIBS) $(APR_LIBS)
