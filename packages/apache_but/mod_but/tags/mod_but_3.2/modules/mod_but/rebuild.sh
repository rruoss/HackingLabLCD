#!/bin/sh
# $Id: rebuild.sh 65 2008-05-30 17:05:05Z droethli $
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

apxs=`findbinary /usr/bin/apxs2 "$APXS"`

apache2ctl stop
make APXS="$apxs" APXSFLAGS="-c -i -a -Wc,-O0 -Wc,-Wall -Wc,-DMOD_BUT_SESSION_COUNT=10 -Wc,-DMOD_BUT_SESSION_HISTORY_COUNT=10 -Wc,-DMOD_BUT_COOKIESTORE_COUNT=30"
apache2ctl start

