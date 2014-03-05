###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_40215.nasl 14 2013-10-27 12:33:37Z jan $
#
# PostgreSQL Multiple Security Vulnerabilities
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
tag_summary = "PostgreSQL is prone to multiple security vulnerabilities.

Attackers can exploit these issues to bypass certain security
restrictions and execute arbitrary Perl or Tcl code.

These issues affect versions prior to the following PostgreSQL
versions:

8.4.4
8.3.11
8.2.17
8.1.21
8.0.25
7.4.29";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100645";
CPE = "cpe:/a:postgresql:postgresql";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-19 12:58:40 +0200 (Wed, 19 May 2010)");
 script_bugtraq_id(40215);
 script_cve_id("CVE-2010-1169","CVE-2010-1170","CVE-2010-1447");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

 script_name("PostgreSQL Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40215");
 script_xref(name : "URL" , value : "http://www.postgresql.org/about/news.1203");
 script_xref(name : "URL" , value : "http://www.postgresql.org/");
 script_xref(name : "URL" , value : "http://www.postgresql.org/support/security");

 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if installed PostgreSQL version is vulnerable.");
 script_category(ACT_GATHER_INFO);
 script_family("Databases");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("postgresql_detect.nasl");
 script_require_ports("Services/postgresql", 5432);
 script_require_keys("PostgreSQL/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");
include("misc_func.inc");
include("host_details.inc");

port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);

if(!port)port = 5432;

if(!get_tcp_port_state(port))exit(0);

if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(version_in_range(version:ver, test_version:"8.4", test_version2:"8.4.3")   ||
   version_in_range(version:ver, test_version:"8.3", test_version2:"8.3.10")  ||
   version_in_range(version:ver, test_version:"8.2", test_version2:"8.2.16")  ||
   version_in_range(version:ver, test_version:"8.1", test_version2:"8.1.20")  ||
   version_in_range(version:ver, test_version:"8.0", test_version2:"8.0.24")  ||
   version_in_range(version:ver, test_version:"7.4", test_version2:"7.4.28")) {
 
     security_hole(port:port);
     exit(0);

}  

exit(0);