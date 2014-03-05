###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mini_web_server_39780.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mini Web Server Cross Site Scripting and Directory Traversal Vulnerabilities
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
tag_summary = "Mini Web Server is prone to a directory-traversal vulnerability and a
cross-site scripting vulnerability because it fails to sufficiently
sanitize user-supplied input.

Exploiting these issues will allow an attacker to execute arbitrary
script code in the browser of an unsuspecting user in the context of
the affected site, and to view arbitrary local files and directories
within the context of the webserver. This may let the attacker steal
cookie-based authentication credentials and other harvested
information may aid in launching further attacks.

Mini Web Server 1.0 is vulnerable; other versions may also be
affected.";


if (description)
{
 script_id(100614);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-30 13:41:49 +0200 (Fri, 30 Apr 2010)");
 script_bugtraq_id(39780);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_name("Mini Web Server Cross Site Scripting and Directory Traversal Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39780");
 script_xref(name : "URL" , value : "http://www.jibble.org/miniwebserver/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if remote Mini Web Server version is	vulnerable");
 script_category(ACT_GATHER_INFO);
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
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner || "Server: JibbleWebServer" >!< banner)exit(0);

version = eregmatch(pattern:"Server: JibbleWebServer/([0-9.]+)", string:banner);
if(isnull(version[1]))exit(0);

if(version_is_equal(version: version[1], test_version:"1.0")) {
  security_warning(port:port);
  exit(0);
}

exit(0);
