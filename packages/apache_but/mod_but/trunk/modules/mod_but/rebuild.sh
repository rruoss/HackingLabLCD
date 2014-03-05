#!/bin/sh
# $Id: rebuild.sh 117 2009-08-06 15:00:50Z droethli $
# Rebuilds mod_but for development.

function findbinary() {
	defloc="$1"
	envloc="$2"
	base=$(basename "$defloc")
	pathloc=$(type -p "$base")
	for loc in "$envloc" "$pathloc" "$defloc"; do
		if [ -x "$loc" ]; then
			echo "$loc"
			return
		fi
	done
	echo "$0: $base not found" >&2
	exit -1
}

apxs=`findbinary /opt/applic/httpd/bin/apxs "$APXS"`

#apache2ctl stop
make APXS="$apxs" APXSFLAGS="-c -i -a -Wc,-O0 -Wc,-Wall -Wc,-DMOD_BUT_SESSION_COUNT=50000 -Wc,-DMOD_BUT_COOKIESTORE_COUNT=100000 -I/opt/applic/pcre/include/"
#apache2ctl start

