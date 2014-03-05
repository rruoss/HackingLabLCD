# OpenVAS Vulnerability Test
# $Id: w3who_dll.nasl 17 2013-10-27 14:01:43Z jan $
# Description: w3who.dll overflow and XSS
#
# Authors:
# Nicolas Gregoire <ngregoire@exaprobe.com>
#
# Copyright:
# Copyright (C) 2004 Nicolas Gregoire <ngregoire@exaprobe.com>
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
tag_summary = "The Windows 2000 Resource Kit ships with a DLL that displays
the browser client context. It lists security identifiers,
privileges and $ENV variables. 

OpenVAS has determined that this file is installed on the remote host.

The w3who.dll ISAPI may allow an attacker to execute arbitrary commands 
on this host, through a buffer overflow, or to mount XSS attacks.";

tag_solution = "Delete this file";

if(description)
{
 script_id(15910);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_cve_id("CVE-2004-1133", "CVE-2004-1134");
 script_bugtraq_id(11820);

 name = "w3who.dll overflow and XSS";

  
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Determines the presence of w3who.dll";


 script_summary(summary);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright("This script is Copyright (C) 2004 Nicolas Gregoire <ngregoire@exaprobe.com>");

 family = "Web application abuses";

 script_family(family);
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.exaprobe.com/labs/advisories/esa-2004-1206.html");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

req  = http_get(item:"/scripts/w3who.dll", port:port);
res  = http_keepalive_send_recv(port:port, data:req);
if("Access Token" >< res)
{
 if(safe_checks()) {
   security_hole(port);
   exit(0);
   }
  
  
  req = string("GET /scripts/w3who.dll?", crap(600), " HTTP/1.1\r\n",
  "Host: ", get_host_name(), "\r\n",
  "User-Agent: OpenVAS\r\n");

 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);

 # The page content is subject to localization
 # Matching on headers and title
 if("HTTP/1.1 500 Server Error" >< r &&
    "<html><head><title>Error</title>" >< r) security_hole(port);
}
exit(0);