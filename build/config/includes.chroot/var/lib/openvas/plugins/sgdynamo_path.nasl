# OpenVAS Vulnerability Test
# $Id: sgdynamo_path.nasl 17 2013-10-27 14:01:43Z jan $
# Description: sgdynamo_path
#
# Authors:
# Scott Shebby (12/2003) 
# Changes by rd :
#	- Description
#	- Support for multiple CGI directories
#	- HTTP KeepAlive support
#	- egrep() instead of eregmatch()
#
# Copyright:
# Copyright (C) 2003 Scott Shebby
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
tag_summary = "The CGI 'sgdynamo.exe' can be tricked into giving the physical path to the 
remote web root.

This information may be useful to an attacker who can use it to make better
attacks against the remote server.";

tag_solution = "None at this time";

# Ref:
# From: "Ruso, Anthony" <aruso@positron.qc.ca>
# To: Penetration Testers <PEN-TEST@SECURITYFOCUS.COM>
# Subject: Sgdynamo.exe Script -- Path Disclosure
# Date: Wed, 16 May 2001 11:55:32 -0400

if(description)
{
 script_id(11954);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "sgdynamo_path";

 script_name(name);
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 summary = "sgdynamo.exe Path Disclosure";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Scott Shebby");
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

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 url = dir + "/sgdynamo.exe?HTNAME=sgdynamo.exe";
 req = http_get(item:url, port:port);
 resp = http_keepalive_send_recv(port:port, data:req);
 if ( resp == NULL ) exit(0);
 path = egrep(pattern:"[aA-zZ]:\\.*sgdynamo\.exe", string:resp);
 if (path) {
   path = ereg_replace(string:path, pattern:".*([aA-zZ]:\\.*sgdynamo\.exe).*", replace:"\1");
   report = 
"
It is possible to obtain the phyiscal path to the remote website by sending
the following request :

" + egrep(pattern:"^GET /", string:req) + "

We determined that the remote web path is : '" + path + "'
This information may be useful to an attacker who can use it to make better
attacks against the remote server.

Solution: None at this time";
   security_warning(port:port, data:report);
   exit(0);
  }
}
