# OpenVAS Vulnerability Test
# $Id: ndcgi.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ndcgi.exe vulnerability
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2003 John Lampe
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
tag_summary = "The file ndcgi.exe exists on this webserver.  
Some versions of this file are vulnerable to remote exploit.";

tag_solution = "remove it from /cgi-bin.
More info can be found at: http://marc.theaimsgroup.com/?l=bugtraq&m=100681274915525&w=2

*** As OpenVAS solely relied on the existence of the ndcgi.exe file, 
*** this might be a false positive";


if(description)
{
 script_id(11730);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2001-0922");
 script_bugtraq_id(3583); 
 
 name = "ndcgi.exe vulnerability";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Checks for the ndcgi.exe file";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2003 John Lampe");
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
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

flag = 0;
directory = "";

no404 = get_kb_item("www/no404/" + port );

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/ndcgi.exe"), port:port)) {
   	if(no404 && is_cgi_installed_ka(item:string(dir, "/openvas" + rand() + ".exe"), port:port)) exit(0);
  	flag = 1;
  	directory = dir;
  	break;
  }
}
 
if (flag) security_hole(port);
