# OpenVAS Vulnerability Test
# $Id: powerportal_path_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: PowerPortal Path Dislcosure
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
tag_summary = "The remote host is using PowerPortal, a content management system, 
written in PHP. 

A vulnerability exists in the remote version of this product which may allow 
a remote attacker to cause the product to disclose the path it is installed 
under. An attacker may use this flaw to gain more knowledge about the setup
of the remote host, and therefore prepare better attacks.";

tag_solution = "Upgrade to the latest version of this software.";

# From: "DarkBicho" <darkbicho@fastmail.fm>
# Subject: Multiple vulnerabilities PowerPortal
# Date: 28.6.2004 03:42

if(description)
{
 script_id(12292);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-0662", "CVE-2004-0664");
 script_bugtraq_id(10622);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "PowerPortal Path Dislcosure";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for the presence of an Path Disclosure bug in PowerPortal";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
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

function check(loc)
{
 req = http_get(item:string(loc, "/modules.php?name=gallery&files=foobar"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if(egrep(pattern:"Warning:", string:r) && 
    egrep(pattern:"opendir", string: r) && 
    egrep(pattern:"failed to open dir: No such file or directory in", string:r))
 {
  security_warning(port);
  exit(0);
 }
}

check(loc:"/");
foreach dir (cgi_dirs())
{
 check(loc:dir);
}
