###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rsa_auth_agent_access_ctrl_bypass_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# EMC RSA Authentication Agent Access Control Bypass Vulnerability (Windows)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802059";
CPE = "cpe:/a:emc:rsa_authentication_agent";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-2287");
  script_bugtraq_id(55662);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-29 12:11:58 +0530 (Thu, 29 Aug 2013)");
  script_name("EMC RSA Authentication Agent Access Control Bypass Vulnerability (Windows)");

  tag_summary =
"The host is installed with RSA Authentication Agent and is prone to security
bypass vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to unspecified configuration, allowing users to login with
Windows credentials, which can be exploited to bypass the RSA authentication
mechanism.";

  tag_impact =
"Successful exploitation will allow attacker to bypass intended token
authentication step and establish a login session to a remote host with
Windows credentials.";

  tag_affected =
"RSA Authentication Agent version 7.1 on Windows XP and Windows 2003";

  tag_solution =
"Upgrade to version 7.1.1 or later,
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
  script_xref(name : "URL" , value : "http://www.osvdb.com/85727");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50735");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/78802");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2012-09/att-0102/ESA-2012-037.txt");
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
ras_auth_ver = "";

## Get app version
ras_auth_ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID);

## Check is it starts with 7.1
if(ras_auth_ver && ras_auth_ver == "7.1")
{
  security_hole(0);
  exit(0);
}
