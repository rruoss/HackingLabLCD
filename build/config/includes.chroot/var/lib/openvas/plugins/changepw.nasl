# OpenVAS Vulnerability Test
# $Id: changepw.nasl 17 2013-10-27 14:01:43Z jan $
# Description: PDGSoft Shopping cart vulnerability
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
tag_summary = "The executables 'redirect.exe' and/or 'changepw.exe' exist on this webserver.  
Some versions of these files are vulnerable to remote exploit.

An attacker can use this hole to gain access to confidential data
or escalate their privileges on the web server.

*** As OpenVAS solely relied on the existence of the redirect.exe or changepw.exe files,
*** this might be a false positive";

tag_solution = "remove them from cgi-bin or scripts folder.";

if(description)
{
 script_id(11723);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1256);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2000-0401");
 
 
 name = "PDGSoft Shopping cart vulnerability";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Checks for PDGSoft Shopping cart executables";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO); # mixed
 
 
 script_copyright("This script is Copyright (C) 2003 John Lampe");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
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

if (get_kb_item("www/" + port + "/no404") ) exit(0);

flag = 0;
directory = "";

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/changepw.exe"), port:port)) {
  	flag = 1;
  	directory = dir;
  	break;
   } 
   if(is_cgi_installed_ka(item:string(dir, "/redirect.exe"), port:port)) {
	flag = 1;
        directory = dir;
        break;
   }
}
 
if (flag) security_hole(port);
