# OpenVAS Vulnerability Test
# $Id: sdbsearch.nasl 16 2013-10-27 13:09:52Z jan $
# Description: sdbsearch.cgi
#
# Authors:
# Renaud Deraison
#
# Copyright:
# Copyright (C) 2004 Renaud Deraison
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
tag_summary = "The SuSE cgi 'sdbsearch.cgi' is installed.
This cgi allows a local (and possibly remote) user
to execute arbitrary commands with the privileges of
the HTTP server.";

tag_solution = "modify the script so that it filters
the HTTP_REFERRER variable, or delete it.";

if(description)
{
 script_id(80084);; 
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2001-1130");
 
 name = "sdbsearch.cgi";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Determines the presence of the sdbsearch.cgi";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("Copyright (C) 2004 Renaud Deraison");

 family = "Web application abuses";

 script_family(family);
 
 script_dependencies("find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


req = string("GET /sdbsearch.cgi?stichwort=anything HTTP/1.1\r\n",
"Referer: http://", get_host_name(), "/../../../../etc\r\n",
"Host: ", get_host_name(), "\r\n\r\n");

r = http_keepalive_send_recv(port:port, data:req);
if( r == NULL )exit(0);
if("htdocs//../../../../etc/keylist.txt" >< r)security_hole(port);

foreach dir (cgi_dirs())
{
req = string("GET ", dir, "/sdbsearch.cgi?stichwort=anything HTTP/1.1\r\n",
"Referer: http://", get_host_name(), "/../../../../etc\r\n",
"Host: ", get_host_name(), "\r\n\r\n");
r = http_keepalive_send_recv(port:port, data:req);
if( r == NULL )exit(0);
if("htdocs//../../../../etc/keylist.txt" >< r)security_hole(port);
}
