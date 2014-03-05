###############################################################################
# OpenVAS Vulnerability Test
# $Id: mapserver_36802.nasl 15 2013-10-27 12:49:54Z jan $
#
# MapServer HTTP Request Processing Integer Overflow Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "MapServer is prone to a remote integer-overflow vulnerability.

An attacker can exploit this issue to execute arbitrary code.
Successful exploits will compromise affected computers. Failed exploit
attempts will result in a denial-of-service condition.

This issue affects MapServer 4.10.x; other versions may be
vulnerable as well.

NOTE: This issue reportedly stems from an incomplete fix for CVE-2009-
      0840, which was discussed in BID 34306 (MapServer Multiple
      Security Vulnerabilities).";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100317);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-26 10:02:32 +0100 (Mon, 26 Oct 2009)");
 script_bugtraq_id(36802);
 script_cve_id("CVE-2009-2281");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 script_name("MapServer HTTP Request Processing Integer Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36802");
 script_xref(name : "URL" , value : "http://mapserver.gis.umn.edu/");

 script_description(desc);
 script_summary("Determine if MapServer is prone to a remote integer-overflow vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_mapserver_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
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

  if(version_in_range(version: version, test_version: "5.4", test_version2: "5.4.2")   ||
     version_in_range(version: version, test_version: "5.2", test_version2: "5.2.3")   ||
     version_in_range(version: version, test_version: "5.0", test_version2: "5.0.3")   ||
     version_in_range(version: version, test_version: "4.10", test_version2: "4.10.5")) {
      security_hole(port:port);
      exit(0);
  }
}

exit(0);
