###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_messaging_gateway_55137.nasl 12 2013-10-27 11:15:33Z jan $
#
# Symantec Messaging Gateway  Cross Site Request Forgery Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "Symantec Messaging Gateway is prone to a cross-site request-forgery
vulnerability

Exploiting this issue may allow a remote attacker to perform certain
unauthorized actions and gain access to the affected application.
Other attacks are also possible.

Symantec Messaging Gateway versions before 10.0 are vulnerable.";

tag_solution = "Vendor updates are available. Please see the reference for more
details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103613";
CPE = "cpe:/a:symantec:messaging_gateway";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(55137);
 script_cve_id("CVE-2012-0308");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 12 $");

 script_name("Symantec Messaging Gateway  Cross Site Request Forgery Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/55137");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-12-03 10:22:01 +0100 (Mon, 03 Dec 2012)");
 script_description(desc);
 script_summary("Determine if installed Symantec Messaging Gateway version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_symantec_messaging_gateway_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(vers =  get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)) {

  if(version_is_less(version: vers, test_version: "10.0.0")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);

