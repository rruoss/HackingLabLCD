###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mariadb_dos_vuln_win.nasl 33 2013-10-31 15:16:09Z veerendragg $
#
# MariaDB Denial Of Service Vulnerability (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804035";
CPE = "cpe:/a:mariadb:mariadb";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 33 $");
  script_cve_id("CVE-2013-1861");
  script_bugtraq_id(58511);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-31 16:16:09 +0100 (Do, 31. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-28 19:18:10 +0530 (Mon, 28 Oct 2013)");
  script_name("MariaDB Denial Of Service Vulnerability (Windows)");

  tag_summary =
"This host is installed with MariaDB and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Get the installed version of MariaDB with the help of detect NVT and
check it is vulnerable or not.";

  tag_insight =
"Numeric calculation error occurs due to an improper handling of geometry
feature while converting a binary string representation of a raw geometry
object to a textual representation.";

  tag_impact =
"Successful exploitation will allow remote attacker to crash the program
via a crafted geometry feature that specifies a large number of points.

Impact Level: Application";

  tag_affected =
"MariaDB version 5.5.x before 5.5.30, 5.3.x before 5.3.13,
5.2.x before 5.2.15, and 5.1.x before 5.1.68 on Windows";

  tag_solution =
"Upgrade to MariaDB 5.1.68, 5.2.15, 5.3.13, 5.5.30 or later,
For updates refer to https://mariadb.org";

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
  script_xref(name : "URL" , value : "http://www.osvdb.org/91415");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52639");
  script_xref(name : "URL" , value : "https://mariadb.atlassian.net/browse/MDEV-4252");
  script_xref(name : "URL" , value : "http://lists.askmonty.org/pipermail/commits/2013-March/004371.html");
  script_summary("Check for the vulnerable version of MariaDB on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MariaDB/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
mariadbPort = "";
mariadbVer = "";

## Linux with backport issue
if(host_runs("Windows") != "yes" && !(get_kb_item("MariaDB/paranoia"))){
  exit(0);
}

## Get MariaDB port
if(!mariadbPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get the MariaDB version
mariadbVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:mariadbPort);
if(isnull(mariadbVer) ||  !(mariadbVer =~ "^(5.1|5.2|5.3|5.5)")){
  exit(0);
}

## Check for vulnerable PostgreSQL versions
if(version_in_range(version:mariadbVer, test_version:"5.1", test_version2:"5.1.67") ||
   version_in_range(version:mariadbVer, test_version:"5.2", test_version2:"5.2.14") ||
   version_in_range(version:mariadbVer, test_version:"5.3", test_version2:"5.3.12") ||
   version_in_range(version:mariadbVer, test_version:"5.5", test_version2:"5.5.29"))
{
  security_warning(port:mariadbPort);
  exit(0);
}
