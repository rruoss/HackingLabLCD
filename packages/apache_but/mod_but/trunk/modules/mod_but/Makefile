#############################################
#
# mod_but Makefile V1.0 by BUT
#
#############################################
# $Id: Makefile 160 2011-02-01 16:45:08Z rblum $

#APXS=/usr/bin/apxs2
#APXS=/zpool/applic/httpd-2.2.14/bin/apxs
#APXS=/zpool/applic/httpd-2.2.6A/bin/apxs
#APXS=/zpool/applic/httpd-2.2.8_01/bin/apxs
#APXS=/opt/applic/http-2.2.10/bin/apxs
#APXS=/opt/applic/httpd-2.2.14/bin/apxs
APXS=/opt/apache_but/httpd/bin/apxs

# CentOS
#APXS=/usr/sbin/apxs

#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /opt/applic/ch-open/httpd-2.2.10/srclib/pcre/
#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /zpool/applic/pcre/pcre-8.0/
#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /root/download/httpd-2.2.6/srclib/pcre/
#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /root/download/httpd-2.2.6/srclib/pcre/
#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /zpool/applic/pcre-7.6/
#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /root/httpd-2.2.14/srclib/pcre/

# CentOS
#APXSFLAGS=-c -i -a -Wc,-O2 -Wc,-Wall -I /usr/include


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
