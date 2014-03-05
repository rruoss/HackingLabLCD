###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lightspeed_40815.nasl 14 2013-10-27 12:33:37Z jan $
#
# LiteSpeed Web Server Source Code Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "LiteSpeed Web Server is prone to a vulnerability that lets attackers
access source code files.

An attacker can exploit this vulnerability to retrieve certain files
from the vulnerable computer in the context of the webserver process.
Information obtained may aid in further attacks.

LiteSpeed Web Server versions prior to 4.0.15 are affected.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100744);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-05 13:46:20 +0200 (Thu, 05 Aug 2010)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-2333");
 script_bugtraq_id(40815);

 script_name("LiteSpeed Web Server Source Code Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40815");
 script_xref(name : "URL" , value : "http://www.litespeedtech.com/latest/litespeed-web-server-4.0.15-released.html");
 script_xref(name : "URL" , value : "http://www.litespeedtech.com");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if is vulnerable to a  Code Information Disclosure Vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","webmirror.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
banner = get_http_banner(port:port);
if(!banner || "LiteSpeed" >!< banner)exit(0);

phps = get_kb_list("www/"+port+"/content/extensions/php");
if(!isnull(phps)) {
  phps = make_list(phps);
} else {
  phps = make_list("/index.php");
}  

foreach php (phps) {

  x++;
  url = php +"\x00.txt";

  if(buf = http_vuln_check(port:port,url:url,pattern:"<\?(php)?",check_header:TRUE)) {
   if("Content-Type: text/plain" >< buf) { 
     if(!http_vuln_check(port:port, url:php,pattern:"<\?(php)?")) {
       security_warning(port:port);
       exit(0);
     }  
    }
  }  
  if(x>=3)exit(0);
}

exit(0);

