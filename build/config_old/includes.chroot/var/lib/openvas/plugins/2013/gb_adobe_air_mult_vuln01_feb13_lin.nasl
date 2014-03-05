##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_mult_vuln01_feb13_lin.nasl 11 2013-10-27 10:12:02Z jan $
#
# Adobe AIR Multiple Vulnerabilities -01 Feb13 (Linux)
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
tag_impact = "Successful exploitation will allow remote attackers to cause buffer overflow,
  remote code execution and corrupt system memory.
  Impact Level: System/Application";

tag_summary = "This host is installed with Adobe AIR and is prone to multiple
  vulnerabilities.";
tag_solution = "Update to version 3.6.0.597 or later,
  For updates refer to http://get.adobe.com/air";
tag_insight = "Multiple flaws due to
  - Dereference already freed memory
  - Use-after-free errors
  - Integer overflow and some unspecified error.";
tag_affected = "Adobe AIR Version prior to 3.6.0.597 on Linux";

if(description)
{
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_id(803412);
  script_version("$Revision: 11 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-15 11:06:40 +0530 (Fri, 15 Feb 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2013-0637", "CVE-2013-0638", "CVE-2013-0639", "CVE-2013-0642",
                "CVE-2013-0644", "CVE-2013-0645", "CVE-2013-0647", "CVE-2013-0649",
                "CVE-2013-1365", "CVE-2013-1366", "CVE-2013-1367", "CVE-2013-1368",
                "CVE-2013-1369", "CVE-2013-1370", "CVE-2013-1372", "CVE-2013-1373",
                "CVE-2013-1374");
  script_bugtraq_id(57929, 57926, 57925, 57923, 57933, 57916, 57927, 57930, 57920,
                    57924, 57922, 57918, 57919, 57912, 57917);
  script_name("Adobe AIR Multiple Vulnerabilities -01 Feb13 (Linux)");
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

  script_xref(name : "URL" , value : "https://lwn.net/Articles/537746");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52166");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-05.html");

  script_description(desc);
  script_summary("Check for the version of Adobe AIR on Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl", "ssh_authorization_init.nasl");
  script_require_keys("Adobe/Air/Linux/Ver");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
playerVer = "";

# Check for Adobe AIR Version prior to 3.6.0.597
playerVer = get_kb_item("Adobe/Air/Linux/Ver");
if(playerVer != NULL)
{
  if(version_is_less(version:playerVer, test_version:"3.6.0.597"))
  {
    security_hole(0);
    exit(0);
  }
}
