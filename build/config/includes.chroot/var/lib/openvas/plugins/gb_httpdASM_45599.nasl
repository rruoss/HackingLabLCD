###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_httpdASM_45599.nasl 13 2013-10-27 12:16:33Z jan $
#
# httpdASM Directory Traversal Vulnerability
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
tag_summary = "httpdASM is prone to a directory-traversal vulnerability because it
fails to sufficiently sanitize user-supplied input.

A remote attacker may leverage this issue to retrieve arbitrary files
in the context of the affected application, potentially revealing
sensitive information that may lead to other attacks.

httpdASM 0.92 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103005);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-03 14:40:34 +0100 (Mon, 03 Jan 2011)");
 script_bugtraq_id(45599);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("httpdASM Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45599");
 script_xref(name : "URL" , value : "http://www.japheth.de/httpdASM.html");
 script_xref(name : "URL" , value : "http://www.johnleitch.net/Vulnerabilities/httpdASM.0.92.Directory.Traversal/73");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if httpdASM is prone to a directory-traversal vulnerability");
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
include("http_keepalive.inc");

port = get_http_port(default:8000);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Server:" >< banner)exit(0);

url = string("/",crap(data:"%2E%2E%5C",length:10*9),"boot.ini");

if(http_vuln_check(port:port, url:url,pattern:"\[boot loader\]")) {
  security_warning(port:port);
  exit(0);
}

exit(0);
