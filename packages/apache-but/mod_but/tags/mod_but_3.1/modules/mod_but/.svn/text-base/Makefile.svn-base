#############################################
#
# mod_but Makefile V1.0 by BUT
#
#############################################

# APXS=/zpool/applic/httpd-2.2.6/bin/apxs
APXS=/zpool/applic/httpd-2.2.6A/bin/apxs
# APXS=/zpool/applic/httpd-2.2.8_01/bin/apxs
# APXSFLAGS=-c -i -a -Wc,-O8 -Wc,-Wall -I /root/download/httpd-2.2.6/srclib/pcre/
APXSFLAGS=-c -i -a -Wc,-O8 -Wc,-Wall -I /root/download/httpd-2.2.6/srclib/pcre/
#APXSFLAGS=-c -i -a -Wc,-O8 -Wc,-Wall -I /zpool/applic/pcre-7.6/
SRC=mod_but.c mod_but_access.c mod_but_request_filter.c mod_but_output_filter.c mod_but_config.c mod_but_session.c mod_but_shm.c mod_but_cookiestore.c mod_but_authorization.c

all: mod_but


mod_but: $(SRC)
	$(APXS) $(APXSFLAGS) $(SRC) 

clean:
	rm -r *.la *.slo *.o  *.lo .libs

