###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_op5_55191.nasl 12 2013-10-27 11:15:33Z jan $
#
# op5 Monitor HTML Injection and SQL Injection Vulnerabilities
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
tag_summary = "op5 Monitor is prone to an HTML-injection vulnerability and an
SQL-injection vulnerability because it fails to sanitize user-
supplied input.

Exploiting these issues may allow an attacker to compromise the
application, access or modify data, exploit vulnerabilities in the
underlying database, execute HTML and script code in the context of
the affected site, steal cookie-based authentication credentials,
or control how the site is rendered to the user; other attacks are
also possible.

op5 Monitor 5.4.2 is vulnerable; other versions may also be affected.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103556";
CPE = "cpe:/a:op5:monitor";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(55191);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:N");

 script_name("op5 Monitor HTML Injection and SQL Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/55191");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-30 10:46:24 +0200 (Thu, 30 Aug 2012)");
 script_description(desc);
 script_summary("Determine if op5 version is vulnerable.");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_op5_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("OP5/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("host_details.inc");
include("version_func.inc");   

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(version_is_equal(version:vers, test_version: "5.4.2")) {

  security_hole(port:port);
  exit(0);
}  

exit(0);



