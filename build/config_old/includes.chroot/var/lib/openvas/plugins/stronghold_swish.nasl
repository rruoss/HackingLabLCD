# OpenVAS Vulnerability Test
# $Id: stronghold_swish.nasl 17 2013-10-27 14:01:43Z jan $
# Description: alya.cgi
#
# Authors:
# Randy Matz <rmatz@ctusa.net>
#
# Copyright:
# Copyright (C) 2003 Randy Matz
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
tag_summary = "An information disclosure vulnerability was reported in a 
sample script provided with Red Hat's Stronghold web server. 
A remote user can determine the web root directory path.

A remote user can send a request to the Stronghold sample script 
swish to cause the script to reveal the full path to the webroot directory. 

Apparently, swish may also display system-specific information in the 
HTML returned by the script";

tag_solution = "remove it";

if(description)
{
 script_id(11230);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_bugtraq_id(4785);
 name = "Stronghold Swish";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 summary = "Checks for the presence of cgi-bin/search";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2003 Randy Matz");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
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





if (is_cgi_installed_ka(port:port, item:"/search"))
{
  req = http_get(item:"/search", port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if ( r == NULL ) exit(0);
   if(egrep(pattern:".*sourcedir value=?/.*stronghold.*", string:r))
     {
     security_warning(port);
     exit(0);
     }
}


foreach dir (cgi_dirs())
{
 if (is_cgi_installed_ka(port:port, item:string(dir, "/search")))
 {
  req = http_get(item:string(dir, "/search"), port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if(r == NULL)exit(0);
  if(egrep(pattern:"sourcedir value=./.*stronghold.*", string:r))
     {
     security_warning(port);
     exit(0);
     }
  }
}
