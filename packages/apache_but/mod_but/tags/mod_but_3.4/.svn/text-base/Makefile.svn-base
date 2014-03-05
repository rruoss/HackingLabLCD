#############################################
#
# mod_but Makefile V1.0 by BUT
#
#############################################
# $Id: Makefile 147 2010-05-30 20:28:01Z ibuetler $

APXS=/usr/sbin/apxs

#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /opt/applic/ch-open/httpd-2.2.10/srclib/pcre/
#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /zpool/applic/pcre/pcre-8.0/
#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /root/download/httpd-2.2.6/srclib/pcre/
#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /root/download/httpd-2.2.6/srclib/pcre/
#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /zpool/applic/pcre-7.6/
#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /root/httpd-2.2.14/srclib/pcre/
APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /usr/include


SRC= \
	mod_but.c \
	mod_but_regexp.c \
	mod_but_redirect.c \
	mod_but_cookie.c \
	mod_but_access_control.c \
	mod_but_request_filter.c \
	mod_but_response_filter.c \
	mod_but_config.c \
	mod_but_session.c \
	mod_but_shm.c

all: mod_but

mod_but: $(SRC)
	$(APXS) $(APXSFLAGS) $(SRC)

clean:
	rm -rf *.la *.slo *.o *.lo .libs

.PHONY: all mod_but clean
