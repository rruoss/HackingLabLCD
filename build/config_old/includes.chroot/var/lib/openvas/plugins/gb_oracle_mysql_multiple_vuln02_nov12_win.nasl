###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_mysql_multiple_vuln02_nov12_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Oracle MySQL Server Multiple Vulnerabilities-02 Nov12 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow an attacker to disclose potentially
  sensitive information, manipulate certain data and cause a DoS
  (Denial of Service).
  Impact Level: Application";
tag_affected = "Oracle MySQL version 5.1.x to 5.1.65 and
  Oracle MySQL version 5.5.x to 5.5.27 on windows";
tag_insight = "The flaws are due to multiple unspecified errors in MySQL server component
  related to server installation and server optimizer.";
tag_solution = "Apply the patch or upgrade to latest version,
  https://support.oracle.com/rs?type=doc&id=1475188.1";
tag_summary = "The host is running Oracle MySQL server and is prone to multiple
  vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803112";
CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-3180", "CVE-2012-3177", "CVE-2012-3160");
  script_bugtraq_id(56003, 56005, 56027);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-26 17:27:23 +0530 (Mon, 26 Nov 2012)");
  script_name("Oracle MySQL Server Multiple Vulnerabilities-02 Nov12 (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51008/");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/51008");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html");

  script_description(desc);
  script_summary("Check for the version of MySQL on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/mysql", 3306);
  script_require_keys("MySQL/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");

sqlPort = "";
mysqlVer = "";

## Exit if its not windows
if(host_runs("Windows")!= "yes"){
  exit(0);
}

## Get the default port
sqlPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!sqlPort){
  sqlPort = 3306;
}

## Check the port status
if(!get_port_state(sqlPort)){
  exit(0);
}

## Get the MySQL version
mysqlVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:sqlPort);
if(isnull(mysqlVer)){
  exit(0);
}

mysqlVer = eregmatch(pattern:"([0-9.a-z]+)", string:mysqlVer);
if(mysqlVer[1])
{
  ## Oracle MySQL version 5.1.x to 5.1.65 and 5.5.x to 5.5.27
  if(version_in_range(version:mysqlVer[1], test_version:"5.1.0", test_version2:"5.1.65") ||
     version_in_range(version:mysqlVer[1], test_version:"5.5.0 ", test_version2:"5.5.27")){
    security_hole(port:sqlPort);
  }
}
