###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_43676.nasl 14 2013-10-27 12:33:37Z jan $
#
# Oracle MySQL Prior to 5.1.51 Multiple Denial Of Service Vulnerabilities
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
tag_summary = "MySQL is prone to multiple denial-of-service vulnerabilities.

An attacker can exploit these issues to crash the database, denying
access to legitimate users.

These issues affect versions prior to MySQL 5.1.51.";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100900";
CPE = "cpe:/a:mysql:mysql";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-11-10 13:18:12 +0100 (Wed, 10 Nov 2010)");
 script_bugtraq_id(43676);
 script_cve_id("CVE-2010-3833","CVE-2010-3834","CVE-2010-3835","CVE-2010-3836","CVE-2010-3837","CVE-2010-3838","CVE-2010-3839","CVE-2010-3840");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("Oracle MySQL Prior to 5.1.51 Multiple Denial Of Service Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43676");
 script_xref(name : "URL" , value : "http://dev.mysql.com/doc/refman/5.1/en/news-5-1-51.html");
 script_xref(name : "URL" , value : "http://www.mysql.com/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed MySQL version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Databases");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 script_require_keys("MySQL/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("host_details.inc");

if (report_paranoia < 2)exit(0); # this nvt is prone to fp

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!port)port = 3306;
if(!get_tcp_port_state(port))exit(0);

if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(version_in_range(version:ver, test_version:"5", test_version2:"5.1.50")) {
  security_warning(port:port);
  exit(0);
}

exit(0);
