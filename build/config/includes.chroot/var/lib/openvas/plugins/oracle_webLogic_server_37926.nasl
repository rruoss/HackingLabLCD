###############################################################################
# OpenVAS Vulnerability Test
# $Id: oracle_webLogic_server_37926.nasl 14 2013-10-27 12:33:37Z jan $
#
# Oracle WebLogic Server Node Manager 'beasvc.exe' Remote Command Execution Vulnerability
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
tag_summary = "Oracle WebLogic Server is prone to a remote command-execution
vulnerability because the software fails to restrict access to
sensitive commands.

Successful attacks can compromise the affected software and possibly
the computer.

Oracle WebLogic Server 10.3.2 is vulnerable; other versions may also
be affected.";

tag_solution = "Vendor updates are available. Please see the vendor advisory
for details.";

if (description)
{
 script_id(100494);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-02-14 12:35:00 +0100 (Sun, 14 Feb 2010)");
 script_bugtraq_id(37926);
 script_cve_id("CVE-2010-0073");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 script_name("Oracle WebLogic Server Node Manager 'beasvc.exe' Remote Command Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37926");
 script_xref(name : "URL" , value : "http://intevydis.blogspot.com/2010/01/oracle-weblogic-1032-node-manager-fun.html");
 script_xref(name : "URL" , value : "http://blogs.oracle.com/security/2010/02/security_alert_for_cve-2010-00.html");
 script_xref(name : "URL" , value : "http://www.oracle.com/technology/products/weblogic/index.html");
 script_xref(name : "URL" , value : "http://www.oracle.com/technology/deploy/security/alerts/alert-cve-2010-0073.html");

 script_description(desc);
 script_summary("Determine if Oracle WebLogic Server version is <= 10.3.2");
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

  if(version_is_less_equal(version: vers, test_version: "10.3.2")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
