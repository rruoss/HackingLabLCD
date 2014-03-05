# OpenVAS Vulnerability Test
# $Id: interchange_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: redhat Interchange
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
tag_summary = "It seems that 'Red Hat Interchange' ecommerce and dynamic 
content management application is running in 'Inet' mode 
on this port.

Versions 4.8.5 and earlier are flawed and may disclose 
contents of sensitive files to attackers.

** OpenVAS neither checked Interchange version nor tried 
** to exploit the vulnerability";

tag_solution = "Upgrade your software if necessary or configure it
for 'Unix mode' communication only.";

# Note: this service is *not* a web server, but it looks like it for 
# find_service
# HEAD / HTTP/1.0	(the only request it seems to recognize)
# HTTP/1.0 200 OK
# Last-modified: [15/August/2002:17:41:40 +0200]
# Content-type: application/octet-stream
#
# GET / HTTP/1.0   (or anything else, even not HTTP: GROUMPF\r\n)
# HTTP/1.0 404 Not found
# Content-type: application/octet-stream
#
# / not a Interchange catalog or help file.

if(description)
{
 script_id(11128);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5453);
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 name = "redhat Interchange";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution; 
 script_description(desc);

 summary = "Redhat Interchange e-commerce application detection";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 script_family("Service detection");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 7786);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

####

include("misc_func.inc");
include("http_func.inc");

port = get_http_port(default:7786);
if ( ! port ) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

send(socket: soc, data: string("OPENVAS / HTTP/1.0", "\r\n",
         "Host: ", get_host_name(), "\r\n\r\n"));
r = recv(socket: soc, length: 1024);
close(soc);

if ("/ not a Interchange catalog or help file" >< r) security_warning(port);

