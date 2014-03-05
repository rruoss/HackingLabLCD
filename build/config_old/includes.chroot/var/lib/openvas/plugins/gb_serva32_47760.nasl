###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_serva32_47760.nasl 13 2013-10-27 12:16:33Z jan $
#
# Serva32 Directory Traversal and Denial of Service Vulnerabilities
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
tag_summary = "Serva32 is prone to a directory-traversal vulnerability and a denial-of-
service vulnerability.

Exploiting these issues will allow attackers to obtain sensitive
information or cause denial-of-service conditions.

Serva32 1.2.00 RC1 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103160);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-05-12 13:24:44 +0200 (Thu, 12 May 2011)");
 script_bugtraq_id(47760);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Serva32 Directory Traversal and Denial of Service Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/47760");
 script_xref(name : "URL" , value : "http://www.vercot.com/~serva/");

 script_description(desc);
 script_summary("Determine if Serva32 is prone to a directory-traversal vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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
if(!banner || "Server: Serva32" >!< banner)exit(0);

url = string("/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/boot.ini"); 

if(http_vuln_check(port:port, url:url,pattern:"\[boot loader\]")) {
       
  security_hole(port:port);
  exit(0);

}

exit(0);
