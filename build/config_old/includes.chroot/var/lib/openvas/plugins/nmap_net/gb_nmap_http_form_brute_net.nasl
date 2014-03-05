###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_http_form_brute_net.nasl 10 2013-10-27 10:03:59Z jan $
#
# Autogenerated NSE wrapper
#
# Authors:
# NSE-Script: Patrik Karlsson
# NASL-Wrapper: autogenerated
#
# Copyright:
# NSE-Script: The Nmap Security Scanner (http://nmap.org)
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Performs brute force password auditing against http form-based authentication.


SYNTAX:

brute.unique:  make sure that each password is only guessed once
(default: true)


http-form-brute.hostname:  sets the host header in case of virtual 
hosting


brute.retries:  the number of times to retry if recoverable failures
occure. (default: 3)


http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).


brute.credfile:  a file containing username and password pairs delimited
by '/'


http.useragent:  The value of the User-Agent header field sent with
requests. By default it is
''Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)''.
A value of the empty string disables sending the User-Agent header field.



brute.threads:  the number of initial worker threads, the number of
active threads will be automatically adjusted.


http-form-brute.passvar:  sets the http-variable name that holds the
password used to authenticate. A simple autodetection of this variable
is attempted.


http-form-brute.uservar:  sets the http-variable name that holds the
username used to authenticate. A simple autodetection of this variable
is attempted.


brute.firstonly:  stop guessing after first password is found
(default: false)


brute.passonly:  iterate over passwords only for services that provide
only a password for authentication. (default: false)


brute.mode:  can be user, pass or creds and determines what mode to run
the engine in.

- user - the unpwdb library is used to guess passwords, every password
password is tried for each user. (The user iterator is in the
outer loop)

- pass - the unpwdb library is used to guess passwords, each password
is tried for every user. (The password iterator is in the
outer loop)

- creds- a set of credentials (username and password pairs) are
guessed against the service. This allows for lists of known
or common username and password combinations to be tested.
If no mode is specified and the script has not added any custom
iterator the pass mode will be enabled.


http-max-cache-size:  The maximum memory size (in bytes) of the cache.



http-form-brute.path:  points to the path protected by authentication


brute.useraspass:  guess the username as password for each user
(default: true)


brute.delay:  the number of seconds to wait between guesses (default: 0)";

if(description)
{
    script_id(104087);
    script_version("$Revision: 10 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:03:59 +0100 (So, 27. Okt 2013) $");
    script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name:"risk_factor", value:"High");
    script_name("Nmap NSE net: http-form-brute");
    desc = "
    Summary:
    " + tag_summary;

    script_description(desc);

    script_summary("Nmap NSE net: http-form-brute");
    script_category(ACT_INIT);
    script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
    script_family("Nmap NSE net");

    script_add_preference(name:"brute.unique", value:"", type:"entry");
    script_add_preference(name:"http-form-brute.hostname", value:"", type:"entry");
    script_add_preference(name:"brute.retries", value:"", type:"entry");
    script_add_preference(name:"http.pipeline", value:"", type:"entry");
    script_add_preference(name:"brute.credfile", value:"", type:"entry");
    script_add_preference(name:"http.useragent", value:"", type:"entry");
    script_add_preference(name:"brute.threads", value:"", type:"entry");
    script_add_preference(name:"http-form-brute.passvar", value:"", type:"entry");
    script_add_preference(name:"http-form-brute.uservar", value:"", type:"entry");
    script_add_preference(name:"brute.firstonly", value:"", type:"entry");
    script_add_preference(name:"brute.passonly", value:"", type:"entry");
    script_add_preference(name:"brute.mode", value:"", type:"entry");
    script_add_preference(name:"http-max-cache-size", value:"", type:"entry");
    script_add_preference(name:"http-form-brute.path", value:"", type:"entry");
    script_add_preference(name:"brute.useraspass", value:"", type:"entry");
    script_add_preference(name:"brute.delay", value:"", type:"entry");

    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
}


include("nmap.inc");

# The corresponding NSE script does't belong to the 'safe' category
if (safe_checks()) exit(0);

phase = 0;
if (defined_func("scan_phase")) {
    phase = scan_phase();
}

if (phase == 1) {
    # Get the preferences
    argv = make_array();

    pref = script_get_preference("brute.unique");
    if (!isnull(pref) && pref != "") {
        argv["brute.unique"] = string('"', pref, '"');
    }
    pref = script_get_preference("http-form-brute.hostname");
    if (!isnull(pref) && pref != "") {
        argv["http-form-brute.hostname"] = string('"', pref, '"');
    }
    pref = script_get_preference("brute.retries");
    if (!isnull(pref) && pref != "") {
        argv["brute.retries"] = string('"', pref, '"');
    }
    pref = script_get_preference("http.pipeline");
    if (!isnull(pref) && pref != "") {
        argv["http.pipeline"] = string('"', pref, '"');
    }
    pref = script_get_preference("brute.credfile");
    if (!isnull(pref) && pref != "") {
        argv["brute.credfile"] = string('"', pref, '"');
    }
    pref = script_get_preference("http.useragent");
    if (!isnull(pref) && pref != "") {
        argv["http.useragent"] = string('"', pref, '"');
    }
    pref = script_get_preference("brute.threads");
    if (!isnull(pref) && pref != "") {
        argv["brute.threads"] = string('"', pref, '"');
    }
    pref = script_get_preference("http-form-brute.passvar");
    if (!isnull(pref) && pref != "") {
        argv["http-form-brute.passvar"] = string('"', pref, '"');
    }
    pref = script_get_preference("http-form-brute.uservar");
    if (!isnull(pref) && pref != "") {
        argv["http-form-brute.uservar"] = string('"', pref, '"');
    }
    pref = script_get_preference("brute.firstonly");
    if (!isnull(pref) && pref != "") {
        argv["brute.firstonly"] = string('"', pref, '"');
    }
    pref = script_get_preference("brute.passonly");
    if (!isnull(pref) && pref != "") {
        argv["brute.passonly"] = string('"', pref, '"');
    }
    pref = script_get_preference("brute.mode");
    if (!isnull(pref) && pref != "") {
        argv["brute.mode"] = string('"', pref, '"');
    }
    pref = script_get_preference("http-max-cache-size");
    if (!isnull(pref) && pref != "") {
        argv["http-max-cache-size"] = string('"', pref, '"');
    }
    pref = script_get_preference("http-form-brute.path");
    if (!isnull(pref) && pref != "") {
        argv["http-form-brute.path"] = string('"', pref, '"');
    }
    pref = script_get_preference("brute.useraspass");
    if (!isnull(pref) && pref != "") {
        argv["brute.useraspass"] = string('"', pref, '"');
    }
    pref = script_get_preference("brute.delay");
    if (!isnull(pref) && pref != "") {
        argv["brute.delay"] = string('"', pref, '"');
    }
    nmap_nse_register(script:"http-form-brute", args:argv);
} else if (phase == 2) {
    res = nmap_nse_get_results(script:"http-form-brute");
    foreach portspec (keys(res)) {
        output_banner = 'Result found by Nmap Security Scanner (http-form-brute.nse) http://nmap.org:\n\n';
        if (portspec == "0") {
            security_hole(data:output_banner + res[portspec], port:0);
        } else {
            v = split(portspec, sep:"/", keep:0);
            proto = v[0];
            port = v[1];
            security_hole(data:output_banner + res[portspec], port:port, protocol:proto);
        }
    }
}