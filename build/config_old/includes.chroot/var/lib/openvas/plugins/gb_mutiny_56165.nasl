###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mutiny_56165.nasl 12 2013-10-27 11:15:33Z jan $
#
# Mutiny  Command Injection Vulnerability
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
tag_summary = "Mutiny is prone to a command-injection vulnerability.

Attackers can exploit this issue to execute arbitrary commands with
root privileges.

Mutiny versions prior to 4.5-1.12 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103589";
CPE = "cpe:/a:mutiny:standard";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(56165);
 script_cve_id("CVE-2012-3001");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_version ("$Revision: 12 $");

 script_name("Mutiny  Command Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/56165");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-10-23 10:29:30 +0200 (Tue, 23 Oct 2012)");
 script_description(desc);
 script_summary("Determine if Mutiny version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_mutiny_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Mutiny/installed");
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

if(!vers =  get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(version_is_less(version:vers, test_version:"4.5-1.12")) {

  security_hole(port:port);
  exit(0);

}  

exit(0);