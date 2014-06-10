
INCLUDES = -I/opt/git/HackingLabLCD/packages/apache_but/apr-iconv-1.2.1/lib -I/opt/git/HackingLabLCD/packages/apache_but/apr-iconv-1.2.1/include  -I/opt/apache_but/apr-1.5.0/include/apr-1 

MODULES_CORE=   _tbl_simple.la euc-jp.la euc-kr.la euc-tw.la gb2312.la \
                iso-10646-ucs-2.la iso-10646-ucs-4.la \
                ucs2-internal.la ucs4-internal.la utf-8.la utf-16.la

MODULES_EXTRA = unicode-1-1-utf-7.la iso-2022-cn.la iso-2022-jp.la \
                iso-2022-jp-2.la iso-2022-kr.la


TARGETS = ${MODULES_CORE} ${MODULES_EXTRA}

# bring in rules.mk for standard functionality
include /opt/git/HackingLabLCD/packages/apache_but/apr-iconv-1.2.1/build/rules.mk

.SUFFIXES:
.SUFFIXES: .c .lo .o .la

.lo.la:
	$(LIBTOOL) --mode=link $(COMPILE) -module -avoid-version -rpath /opt/apache_but/apr-iconf-1.2.1/lib/iconv $(LT_LDFLAGS) $(ALL_LDFLAGS) -o $@ $<
