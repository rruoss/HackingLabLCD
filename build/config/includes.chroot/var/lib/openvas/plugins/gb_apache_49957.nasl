###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_49957.nasl 18 2013-10-27 14:14:13Z jan $
#
# Apache HTTP Server 'mod_proxy' Reverse Proxy Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "Apache HTTP Server is prone to an information disclosure
vulnerability.

An attacker can exploit this vulnerability to gain access to sensitive
information.";

tag_solution = "The vendor released an update. Please see the references for details.";

if (description)
{
 script_id(103293);
 script_bugtraq_id(49957,50802);
 script_cve_id("CVE-2011-3368","CVE-2011-4317");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_version ("$Revision: 18 $");

 script_name("Apache HTTP Server 'mod_proxy' Reverse Proxy Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49957");
 script_xref(name : "URL" , value : "http://httpd.apache.org/");
 script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Oct/232");

 script_description(desc);
 script_summary("Determine if installed Apache is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(banner && ("Apache" >!< banner && banner !~ "HTTP/1.. 50[2|3]"))exit(0);

req = string("GET @localhost HTTP/1.0\r\n\r\n");
result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(ereg(pattern:"HTTP/1.. 400", string:result))exit(0); # 400 means not vulnerable

ip3 = "5555.6666.7777.8888"; 

req = string("GET @", ip3 ," HTTP/1.0\r\n\r\n");

result2 = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(ereg(pattern:"HTTP/1.. 200", string:result2) && "Bad Gateway" >< result2 ||
   ereg(pattern:"HTTP/1.. 502", string:result2)) { 

  security_warning(port:port);
  exit(0);
  
}  

# CVE-2011-4317
req = string("GET @localhost::65535 HTTP/1.0\r\n\r\n");
result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(ereg(pattern:"HTTP/1.. 503", string:result)) {
  security_warning(port:port);
  exit(0);
}  

exit(0);
