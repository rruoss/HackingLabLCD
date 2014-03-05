###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mariadb_change_user_cmd_sec_bypass_vuln.nasl 51 2013-11-08 15:12:40Z veerendragg $
#
# MariaDB 'COM_CHANGE_USER' Command Insecure Salt Generation Security Bypass Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804037";
CPE = "cpe:/a:mariadb:mariadb";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 51 $");
  script_cve_id("CVE-2012-5627");
  script_bugtraq_id(56837);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-11-08 16:12:40 +0100 (Fr, 08. Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-06 15:34:28 +0530 (Wed, 06 Nov 2013)");
  script_name("MariaDB 'COM_CHANGE_USER' Command Insecure Salt Generation Security Bypass Vulnerability");

  tag_summary =
"This host is running MariaDB and is prone to security bypass vulnerability.";

  tag_insight =
"Flaw that is triggered when a remote attacker attempts to login to a user's
account via the COM_CHANGE_USER command. This command fails to properly
disconnect the attacker from the server upon a failed login attempt.";

  tag_vuldetect =
"Get the installed version of MariaDB with the help of detect NVT and
check it is vulnerable or not.";

  tag_impact =
"Successful exploitation will allow remote attackers to more easily
gain access to a user's account via a brute-force attack.

Impact Level: Application";

  tag_affected =
"MariaDB versions 5.5.x before 5.5.29, 5.3.x before 5.3.12, and
5.2.x before 5.2.14";

  tag_solution = "Upgrade to MariaDB version 5.2.14, 5.3.12, 5.5.29 or later,
For updates refer to  https://mariadb.org";

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
  script_xref(name : "URL" , value : "http://www.osvdb.com/88415");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52015");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Dec/58");
  script_xref(name : "URL" , value : "https://mariadb.atlassian.net/browse/MDEV-3915");
  script_summary("Check for the vulnerable version of MariaDB");
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
if(isnull(mariadbVer) ||  !(mariadbVer =~ "^(5.2|5.3|5.5)")){
  exit(0);
}

## Check for vulnerable MariaDB versions
if(version_in_range(version:mariadbVer, test_version:"5.2", test_version2:"5.2.13") ||
   version_in_range(version:mariadbVer, test_version:"5.3", test_version2:"5.3.11") ||
   version_in_range(version:mariadbVer, test_version:"5.5", test_version2:"5.5.28"))
{
  security_warning(port:mariadbPort);
  exit(0);
}
