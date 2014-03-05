###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_unspecified_vuln02_oct13_win.nasl 33 2013-10-31 15:16:09Z veerendragg $
#
# Oracle MySQL Server Component 'Optimizer' Unspecified vulnerability Oct-2013 (Windows)
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804033";
CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 33 $");
  script_cve_id("CVE-2013-3839");
  script_bugtraq_id(63109);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-31 16:16:09 +0100 (Do, 31. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-28 16:26:24 +0530 (Mon, 28 Oct 2013)");
  script_name("Oracle MySQL Server Component 'Optimizer' Unspecified vulnerability Oct-2013 (Windows)");

  tag_summary =
"This host is running Oracle MySQL and is prone to unspecified vulnerability.";

  tag_insight =
"Unspecified error in the MySQL Server component via unknown vectors related
to Optimizer.";

  tag_vuldetect =
"Get the installed version of MySQL with the help of detect NVT and check
it is vulnerable or not.";

  tag_impact =
"Successful exploitation will allow remote attackers to disclose sensitive
information, manipulate certain data, cause a DoS (Denial of Service) and
bypass certain security restrictions.

Impact Level: Application";

  tag_affected =
"Oracle MySQL versions 5.1.51 through 5.1.70, 5.5.10 through 5.5.32, and 5.6.x
through 5.6.12.";

  tag_solution = "Apply the patch from below link,
http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html";

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
  script_xref(name : "URL" , value : "http://www.osvdb.com/98508");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/55327");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html");
  script_summary("Check for the vulnerable version of Oracle MySQL on windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
mysqlVer = "";
sqlPort = "";

## Linux with backport issue
if(host_runs("Windows") != "yes" && !(get_kb_item("MySQL/paranoia"))){
  exit(0);
}

## Get Port
if(!sqlPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get version
if(!mysqlVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:sqlPort)){
  exit(0);
}

if(mysqlVer =~ "^(5\.(1|5|6))")
{
  if(version_in_range(version:mysqlVer, test_version:"5.1.51", test_version2:"5.1.70") ||
     version_in_range(version:mysqlVer, test_version:"5.5.10", test_version2:"5.5.32") ||
     version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.12"))
  {
    security_warning(sqlPort);
    exit(0);
  }
}
