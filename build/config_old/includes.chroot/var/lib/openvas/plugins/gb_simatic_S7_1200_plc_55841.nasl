###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_S7_1200_plc_55841.nasl 12 2013-10-27 11:15:33Z jan $
#
# Siemens SIMATIC S7-1200 PLC 'web server' Component Cross Site Scripting Vulnerability
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
tag_summary = "Siemens SIMATIC S7-1200 Programmable Logic Controller (PLC) is prone
to a cross-site scripting vulnerability because it fails to properly
sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This can allow the attacker to steal cookie-based authentication
credentials and launch other attacks.";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103584";
CPE = "cpe:/h:siemens:simatic_s7-1200_plc";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(55841);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

 script_name("Siemens SIMATIC S7-1200 PLC 'web server' Component Cross Site Scripting Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/55841");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-10-10 12:27:02 +0200 (Wed, 10 Oct 2012)");
 script_description(desc);
 script_summary("Determine if SIMATIC firmware version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_simatic_S7_1200_plc_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_udp_ports("Services/snmp", 161);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("simatic_s7_1200/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!version = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(version_is_equal(version:version, test_version:"2.0.2") ||
   version_is_equal(version:version, test_version:"2.0.3")) {
 
    security_warning(port:port);
    exit(0);

}
   
exit(0);
