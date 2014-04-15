#
# export_vars.sh
#
# This shell script is used to export vars to the application using the
# APRUTIL library. This script should be "sourced" to ensure the variable
# values are set within the calling script's context. For example:
#
#   $ . path/to/apr-util/export_vars.sh
#

APRUTIL_EXPORT_INCLUDES="-I/opt/git/HackingLabLCD/packages/apache_but/apr-util-1.5.3/xml/expat/lib -I/opt/apache_but/apr-iconf-1.2.1//include/apr-1 -I/opt/apache_but/apr-iconf-1.2.1//include"
APRUTIL_EXPORT_LIBS="/opt/git/HackingLabLCD/packages/apache_but/apr-util-1.5.3/xml/expat/libexpat.la"
APRUTIL_LDFLAGS="-L/opt/apache_but/apr-iconf-1.2.1//lib"
