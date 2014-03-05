# OpenVAS Vulnerability Test
# $Id: iis_dot_cnf.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Check for IIS .cnf file leakage
#
# Authors:
# John Lampe (j_lampe@bellsouth.net)
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2003 John Lampe....j_lampe@bellsouth.net
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
tag_summary = "The IIS web server may allow remote users to read sensitive information
from .cnf files. This is not the default configuration.

Example, http://target/_vti_pvt%5csvcacl.cnf, access.cnf,
        svcacl.cnf, writeto.cnf, service.cnf, botinfs.cnf,
        bots.cnf, linkinfo.cnf and services.cnf";

tag_solution = "If you do not need .cnf files, then delete them, otherwise use
suitable access control lists to ensure that the .cnf files are not
world-readable by Anonymous users.";

if(description)
{
  script_id(10575);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-1717");
  script_bugtraq_id(4078);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  
  script_name("Check for IIS .cnf file leakage");
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);
  script_summary("Check for existence of world-readable .cnf files");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2003 John Lampe....j_lampe@bellsouth.net");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);   
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.safehack.com/Advisory/IIS5webdir.txt");
  exit(0);
}



#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


    
port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/no404" ) )  exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
if(get_port_state(port)) {
   fl[0] = "/_vti_pvt%5caccess.cnf";
   fl[1] = "/_vti_pvt%5csvcacl.cnf";
   fl[2] = "/_vti_pvt%5cwriteto.cnf";
   fl[3] = "/_vti_pvt%5cservice.cnf";
   fl[4] = "/_vti_pvt%5cservices.cnf";
   fl[5] = "/_vti_pvt%5cbotinfs.cnf";
   fl[6] = "/_vti_pvt%5cbots.cnf";
   fl[7] = "/_vti_pvt%5clinkinfo.cnf";

   
   for(i = 0 ; fl[i] ; i = i + 1)
   {
    if(is_cgi_installed_ka(item:fl[i], port:port)){
	res = http_keepalive_send_recv(data:http_get(item:fl[i], port:port), port:port, bodyonly:1);
	data = "
The IIS web server may allow remote users to read sensitive information
from .cnf files. This is not the default configuration.

Example : requesting " + fl[i] + " produces the following data : 

" + res + "

See also : http://www.safehack.com/Advisory/IIS5webdir.txt
Solution: If you do not need .cnf files, then delete them, otherwise use
suitable access control lists to ensure that the .cnf files are not
world-readable by Anonymous users.";

	
   	security_warning(port:port, data:data);
	exit(0);
	}
   }
}
