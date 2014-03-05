###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_mult_vuln01_apr13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Adobe AIR Multiple Vulnerabilities -01 April 13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code or cause denial-of-service condition.
  Impact Level: System/Application";

tag_affected = "Adobe AIR Version prior to 3.6.0.6090 on Windows.";
tag_insight = "Multiple flaws due to,
  - Heap based overflow via unspecified vectors.
  - Integer overflow via unspecified vectors.
  - Use-after-free errors.";
tag_solution = "Upgrade to version 3.6.0.6090 or later,
  For updates refer to http://get.adobe.com/air";
tag_summary = "This host is installed with Adobe AIR and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803377);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1375","CVE-2013-1371","CVE-2013-0650","CVE-2013-0646");
  script_bugtraq_id(58439,58438,58440,58436);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-18 15:30:14 +0530 (Thu, 18 Apr 2013)");
  script_name("Adobe AIR Multiple Vulnerabilities -01 April 13 (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52590");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-09.html");
  script_xref(name : "URL" , value : "https://www.cert.be/pro/advisories/adobe-flash-player-air-multiple-vulnerabilities-2");
  script_summary("Check for the vulnerable version of Adobe AIR on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

## Variable Initialization
playerVer = "";

# Check for Adobe AIR Version prior to 3.6.0.6090
playerVer = get_kb_item("Adobe/Air/Win/Ver");
if(playerVer != NULL)
{
  if(version_is_less(version:playerVer, test_version:"3.6.0.6090"))
  {
    security_hole(0);
    exit(0);
  }
}