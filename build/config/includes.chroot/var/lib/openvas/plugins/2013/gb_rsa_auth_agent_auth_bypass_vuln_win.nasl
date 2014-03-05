###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rsa_auth_agent_auth_bypass_vuln_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# RSA Authentication Agent Authentication Bypass Vulnerability (Windows)
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
  Impact Level: System/Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803749";
CPE = "cpe:/a:emc:rsa_authentication_agent";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-0931");
  script_bugtraq_id(58248);
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-28 11:21:00 +0530 (Wed, 28 Aug 2013)");
  script_name("RSA Authentication Agent Authentication Bypass Vulnerability (Windows)");

  tag_summary =
"The host is installed with RSA Authentication Agent and is prone to
authentication bypass vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is triggered when a session is activated from the active screensaver
after the Quick PIN Unlock timeout has expired, which will result in an
incorrect prompt for a PIN as opposed to a prompt for the full passcode.";

  tag_impact =
"Successful exploitation will allow local attacker to bypass certain security
restrictions and gain unauthorized privileged access.";

  tag_affected =
"RSA Authentication Agent version 7.1.x before 7.1.2 on Windows.";

  tag_solution =
"Upgrade to version 7.1.2 or later,
For updates refer to http://www.rsa.com/node.aspx?id=2575";

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
  script_xref(name : "URL" , value : "http://www.osvdb.org/90743");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1028230");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/438433.php");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120606");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Mar/att-0/ESA-2013-012.txt");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2013-03/att-0001/ESA-2013-012.txt");
  script_summary("Check for the vulnerable version of RSA Authentication Agent on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_rsa_auth_agent_detect_win.nasl");
  script_mandatory_keys("RSA/AuthenticationAgent/Ver");
  exit(0);
}


include("secpod_reg.inc");
include("version_func.inc");
include("host_details.inc");

## Windows XP/2003 are vulnerable
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) <= 0){
  exit(0);
}

## Variable Initialization
rasAutVer = "";

## Get version from KB
rasAutVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID);
if(rasAutVer && rasAutVer =~ "^7.1")
{
  ## Check for version
  if(version_is_less(version:rasAutVer, test_version:"7.1.2"))
  {
    security_hole(0);
    exit(0);
  }
}
