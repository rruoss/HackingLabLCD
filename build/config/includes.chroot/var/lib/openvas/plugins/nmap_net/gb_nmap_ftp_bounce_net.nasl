###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_ftp_bounce_net.nasl 10 2013-10-27 10:03:59Z jan $
#
# Autogenerated NSE wrapper
#
# Authors:
# NSE-Script: Marek Majkowski
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
tag_summary = "Checks to see if an FTP server allows port scanning using the FTP bounce method.


SYNTAX:

ftp-bounce.username:  Username to log in with. Default
''anonymous''.


ftp-bounce.password:  Password to log in with. Default
''IEUser@''.";

if(description)
{
    script_id(104162);
    script_version("$Revision: 10 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:03:59 +0100 (So, 27. Okt 2013) $");
    script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
    script_tag(name:"risk_factor", value:"None");
    script_name("Nmap NSE net: ftp-bounce");
    desc = "
    Summary:
    " + tag_summary;

    script_description(desc);

    script_summary("Nmap NSE net: ftp-bounce");
    script_category(ACT_INIT);
    script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
    script_family("Nmap NSE net");

    script_add_preference(name:"ftp-bounce.username", value:"", type:"entry");
    script_add_preference(name:"ftp-bounce.password", value:"", type:"entry");

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

    pref = script_get_preference("ftp-bounce.username");
    if (!isnull(pref) && pref != "") {
        argv["ftp-bounce.username"] = string('"', pref, '"');
    }
    pref = script_get_preference("ftp-bounce.password");
    if (!isnull(pref) && pref != "") {
        argv["ftp-bounce.password"] = string('"', pref, '"');
    }
    nmap_nse_register(script:"ftp-bounce", args:argv);
} else if (phase == 2) {
    res = nmap_nse_get_results(script:"ftp-bounce");
    foreach portspec (keys(res)) {
        output_banner = 'Result found by Nmap Security Scanner (ftp-bounce.nse) http://nmap.org:\n\n';
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