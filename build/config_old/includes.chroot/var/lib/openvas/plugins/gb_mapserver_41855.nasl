###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mapserver_41855.nasl 14 2013-10-27 12:33:37Z jan $
#
# MapServer Buffer Overflow and Unspecified Security Vulnerabilities
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
tag_solution = "The vendor has released updates to address these issues. Please see
the references for more information.

UPDATE (June 22, 2009): Fixes for the buffer-overflow vulnerable
tracked by CVE-2009-0840 are incomplete; MapServer 4.10.4 and 5.2.2
may still be vulnerable to this issue.";

tag_summary = "MapServer is prone to multiple remote vulnerabilities, including a buffer-
overflow vulnerability and an unspecified security vulnerability
affecting the CGI command-line debug arguments.

An attacker can exploit these issues to execute arbitrary code within
the context of the affected application or crash the application.
Other attacks are also possible.

Versions prior to MapServer 5.6.4 and 4.10.6 are vulnerable.";


if (description)
{
 script_id(100737);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-02 19:12:50 +0200 (Mon, 02 Aug 2010)");
 script_bugtraq_id(41855);
 script_cve_id("CVE-2010-2539","CVE-2010-2540");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("MapServer Buffer Overflow and Unspecified Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41855");
 script_xref(name : "URL" , value : "http://trac.osgeo.org/mapserver/ticket/3484");
 script_xref(name : "URL" , value : "http://trac.osgeo.org/mapserver/ticket/3485");
 script_xref(name : "URL" , value : "http://lists.osgeo.org/pipermail/mapserver-users/2010-July/066052.html");
 script_xref(name : "URL" , value : "http://mapserver.gis.umn.edu/");

 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if installed MapServer version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_mapserver_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!version = get_kb_item(string("www/", port, "/MapServer")))exit(0);

if(!isnull(version)) {

  if(version_in_range(version: version, test_version: "5.6", test_version2: "5.6.3")   ||
     version_in_range(version: version, test_version: "4.10", test_version2: "4.10.5")) {
      security_hole(port:port);
      exit(0);
  }
}

exit(0);
