###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_weblogic_41620.nasl 14 2013-10-27 12:33:37Z jan $
#
# Oracle WebLogic Server Encoded URL Remote Vulnerability
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
tag_summary = "Oracle WebLogic Server is prone to a remote vulnerability.

The vulnerability can be exploited over the 'HTTP' protocol. For an
exploit to succeed, the attacker must have 'Plugins for Apache, Sun
and IIS web servers' privileges.

This vulnerability affects the following supported versions:
7. SP7, 8.1 SP6, 9.0, 9.1, 9.2 MP3, 10.0 MP2, 10.3.2, 10.3.3";

tag_solution = "Vendor updates are available. Please contact the vendor for more
information.";

if (description)
{
 script_id(100714);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-14 13:50:55 +0200 (Wed, 14 Jul 2010)");
 script_bugtraq_id(41620);
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2010-2375");

 script_name("Oracle WebLogic Server Encoded URL Remote Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41620");
 script_xref(name : "URL" , value : "http://www.vsecurity.com/resources/advisory/20100713-1/");
 script_xref(name : "URL" , value : "http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpujul2010.html");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if Oracle WebLogic Server version is <= 10.3.3");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("oracle_webLogic_server_detect.nasl");
 script_require_ports("Services/www", 7001);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:7001);
if(!get_port_state(port))exit(0);

if(!vers = get_kb_item(string("www/", port, "/WebLogic_Server")))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less_equal(version: vers, test_version: "10.3.3")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);


