# OpenVAS Vulnerability Test
# $Id: dwhttp_format_string.nasl 17 2013-10-27 14:01:43Z jan $
# Description: dwhttpd format string
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote web server is vulnerable to a format string attack.

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.";

tag_solution = "upgrade your software or protect it with a filtering reverse proxy";

# This script could also cover BID:1556 and CVE-2000-0697
#
# References:
#
# Date:  Thu, 1 Aug 2002 16:31:40 -0600 (MDT)		      
# From: "ghandi" <ghandi@mindless.com>			      
# To: bugtraq@securityfocus.com				      
# Subject: Sun AnswerBook2 format string and other vulnerabilities
#
# Affected:
# dwhttp/4.0.2a7a, dwhttpd/4.1a6
# And others?

if(description)
{
 script_id(11075);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5384);
 script_cve_id("CVE-1999-1417");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 name = "dwhttpd format string";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "DynaWeb server vulnerable to format string";
 script_summary(summary);
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Gain a shell remotely";
 script_family(family);
 script_require_ports("Services/www", 8888);
 script_dependencies("find_service.nasl", "httpver.nasl", "http_version.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

########

include("http_func.inc");
include("misc_func.inc");

function check(port)
{
 banner = get_http_banner(port: port);
 if ( "dwhttp/" >!< banner ) return 0;

 if (safe_checks()) 
 {
	if (egrep(string: banner, pattern: "^Server: *dwhttp/4.(0|1[^0-9])"))
		security_hole(port);
	return(0);
 }

 if(http_is_dead(port: port)) { return(0); }

 soc = http_open_socket(port);
 if(! soc) return(0);

 i = string("/", crap(data:"%n", length: 100));
 r = http_get(item:i, port:port);

 send(socket:soc, data: r);
 r = http_recv(socket:soc);
 http_close_socket(soc);

 if(http_is_dead(port: port, retry:2)) { security_hole(port); }
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8888);
foreach port (ports)
{
 check(port:port);
}
