###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_dos_n_spoofing_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# MySQL Denial Of Service and Spoofing Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation could allow users to cause a Denial of Service and
  man-in-the-middle attackers to spoof arbitrary SSL-based MySQL servers via
  a crafted certificate.
  Impact Level: Application";
tag_affected = "MySQL 5.0.x before 5.0.88 and 5.1.x before 5.1.41 on all running platform.";
tag_insight = "The flaws are due to:
  - mysqld does not properly handle errors during execution of certain SELECT
    statements with subqueries, and does not preserve certain null_value flags
    during execution of statements that use the 'GeomFromWKB()' function.
  - An error in 'vio_verify_callback()' function in 'viosslfactories.c', when
    OpenSSL is used, accepts a value of zero for the depth of X.509 certificates.";
tag_solution = "Upgrade to MySQL version 5.0.88 or 5.1.41
  For updates refer to http://dev.mysql.com/downloads";
tag_summary = "The host is running MySQL and is prone to Denial Of Service
  and Spoofing Vulnerabilities";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801064";
CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-04 14:17:59 +0100 (Fri, 04 Dec 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4019","CVE-2009-4028");
  script_name("MySQL Denial Of Service and Spoofing Vulnerabilities");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


  script_description(desc);
  script_summary("Check for the version of MySQL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://bugs.mysql.com/47780");
  script_xref(name : "URL" , value : "http://bugs.mysql.com/47320");
  script_xref(name : "URL" , value : "http://marc.info/?l=oss-security&amp;m=125881733826437&amp;w=2");
  script_xref(name : "URL" , value : "http://dev.mysql.com/doc/refman/5.0/en/news-5-0-88.html");
  exit(0);
}


include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");


sqlPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!sqlPort){
  sqlPort = 3306;
}

if(!get_port_state(sqlPort)){
  exit(0);
}

mysqlVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:sqlPort);
if(isnull(mysqlVer)){
  exit(0);
}

mysqlVer = eregmatch(pattern:"([0-9.a-z]+)", string:mysqlVer);
if(!isnull(mysqlVer[1]))
{
  if(version_in_range(version:mysqlVer[1], test_version:"5.0",test_version2:"5.0.87") ||
     version_in_range(version:mysqlVer[1], test_version:"5.1",test_version2:"5.1.40")){
    security_hole(sqlPort);
  }
}
