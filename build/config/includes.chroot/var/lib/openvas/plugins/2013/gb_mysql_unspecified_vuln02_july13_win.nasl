###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_unspecified_vuln02_july13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# MySQL Unspecified vulnerabilities-02 July-2013 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "
  Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803724";
CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3812", "CVE-2013-3809", "CVE-2013-3793");
  script_bugtraq_id(61249, 61272, 61264);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-29 17:20:08 +0530 (Mon, 29 Jul 2013)");
  script_name("MySQL Unspecified vulnerabilities-02 July-2013 (Windows)");

  tag_summary =
"This host is running MySQL and is prone to multiple unspecified
vulnerabilities.";

  tag_insight =
"Unspecified errors in the MySQL Server component via unknown vectors related
to Server Replication, Audit Log and Data Manipulation Language.";

  tag_vuldetect =
"Get the installed version of MySQL with the help of detect NVT and
check it is vulnerable or not.";

  tag_impact =
"Successful exploitation will allow remote authenticated users to affect
integrity and availability via unknown vectors and cause denial of service.";

  tag_affected =
"Oracle MySQL 5.5.31 and earlier, 5.6.11 and earlier on Windows";

  tag_solution = "Apply the patch from below link,
http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html ";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/95328");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html");
  script_summary("Check for the vulnerable version of MySQL on windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");
  exit(0);
}

include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");

## Exit if its not windows
if(host_runs("Windows") != "yes"){
  exit(0);
}

## Variable Initialization
sqlPort = "";
mysqlVer = "";

sqlPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!sqlPort){
  sqlPort = 3306;
}

if(!get_port_state(sqlPort)){
  exit(0);
}

mysqlVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:sqlPort);
if(mysqlVer && mysqlVer =~ "^(5\.(5|6))")
{
  if(version_in_range(version:mysqlVer, test_version:"5.5", test_version2:"5.5.31") ||
     version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.11"))
  {
    security_warning(sqlPort);
    exit(0);
  }
}