#############################################
#
# mod_but Makefile V1.0 by BUT
#
#############################################
# $Id: Makefile 62 2008-05-30 14:46:39Z droethli $

#APXS=/zpool/applic/httpd-2.2.6/bin/apxs
#APXS=/zpool/applic/httpd-2.2.6A/bin/apxs
#APXS=/zpool/applic/httpd-2.2.8_01/bin/apxs
APXS=/usr/bin/apxs2

#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /root/download/httpd-2.2.6/srclib/pcre/
#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /root/download/httpd-2.2.6/srclib/pcre/
#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /zpool/applic/pcre-7.6/
APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall

SRC= \
	mod_but.c \
	mod_but_redirect.c \
	mod_but_regexp.c \
	mod_but_access.c \
	mod_but_request_filter.c \
	mod_but_output_filter.c \
	mod_but_config.c \
	mod_but_session.c \
	mod_but_shm.c \
	mod_but_cookiestore.c \
	mod_but_authorization.c

all: mod_but

mod_but: $(SRC)
	$(APXS) $(APXSFLAGS) $(SRC)

clean:
	rm -rf *.la *.slo *.o *.lo .libs

.PHONY: all mod_but clean
