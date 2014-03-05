###############################################################################
# OpenVAS Vulnerability Test
# $Id: lighttpd_38036.nasl 14 2013-10-27 12:33:37Z jan $
#
# lighttpd Slow Request Handling Remote Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer
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
tag_summary = "lighttpd is prone to a denial-of-service vulnerability.

Remote attackers can exploit this issue to cause the application to
hang, denying service to legitimate users.";

tag_solution = "SVN fixes and patches are available. Please see the references
for details.";

if (description)
{
 script_id(100480);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-02-02 21:07:02 +0100 (Tue, 02 Feb 2010)");
 script_bugtraq_id(38036);
 script_cve_id("CVE-2010-0295");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("lighttpd Slow Request Handling Remote Denial Of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38036");
 script_xref(name : "URL" , value : "http://www.lighttpd.net/");
 script_xref(name : "URL" , value : "http://redmine.lighttpd.net/issues/2147");
 script_xref(name : "URL" , value : "http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2010_01.txt");

 script_description(desc);
 script_summary("Determine if lighttpd version is <= 1.4.26");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if("lighttpd/" >!< banner)exit(0);

version = eregmatch(pattern: "Server: lighttpd/([0-9.]+)", string: banner);
if(isnull(version[1]))exit(0);

if(version_is_less_equal(version: version[1], test_version: "1.4.25")) {
  security_warning(port:port);
  exit(0);
}

exit(0);
