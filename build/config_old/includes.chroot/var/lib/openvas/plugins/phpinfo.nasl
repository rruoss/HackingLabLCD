# OpenVAS Vulnerability Test
# $Id: phpinfo.nasl 17 2013-10-27 14:01:43Z jan $
# Description: phpinfo.php
#
# Authors:
# Randy Matz <rmatz@ctusa.net>
# Improvement by rd: look in every dir for info.php and phpinfo.php
# not just in cgi-bin
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
tag_summary = "Many PHP installation tutorials instruct the user to create
a file called phpinfo.php.  This file is often times left in 
the root directory after completion.
Some of the information that can be garnered from this file 
includes:  The username of the user who installed php, if they 
are a SUDO user, the IP address of the host, the web server 
version, The system version(unix / linux), and the root 
directory of the web server.";

tag_solution = "remove it";

if(description)
{
 script_id(11229);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 
 name = "phpinfo.php";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 summary = "Checks for the presence of phpinfo.php";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2003 Randy Matz");
 family = "Web application abuses";
 script_family(family);
 script_require_ports("Services/www", 80);
 script_dependencies("http_version.nasl");
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
if(!can_host_php(port:port))exit(0);

dirs = get_kb_list(string("www/", port, "/content/directories"));
if(isnull(dirs))dirs = make_list("");
else dirs = make_list("", dirs);

rep = NULL;

foreach dir (dirs)
{
 req = http_get(item:string(dir, "/phpinfo.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("<title>phpinfo()</title>" >< res)
 	rep += dir + '/phpinfo.php\n';

  req = http_get(item:string(dir, "/info.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if( res == NULL ) exit(0);
  if("<title>phpinfo()</title>" >< res)	
  	rep += dir + '/info.php\n';
}


if(rep != NULL)
{
 report = string("
The following files are calling the function phpinfo() which
disclose potentially sensitive information to the remote attacker : 
", rep, "

Solution: Delete them or restrict access to them");

 security_hole(port:port, data:report);
}
