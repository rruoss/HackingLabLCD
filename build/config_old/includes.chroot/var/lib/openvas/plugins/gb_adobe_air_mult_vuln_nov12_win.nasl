###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_mult_vuln_nov12_win.nasl 18 2013-10-27 14:14:13Z jan $
#
# Adobe Air Multiple Vulnerabilities - November12 (Windows)
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
tag_impact = "Successful exploitation will allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the affected
  application.
  Impact Level: System/Application";
tag_affected = "Adobe AIR version 3.4.0.2710 and earlier on Windows";
tag_insight = "Multiple unspecified errors exists due to memory corruption, buffer overflow
  that could lead to code execution.";
tag_solution = "Update to Adobe Air version 3.5.0.600 or later,
  For updates refer to http://get.adobe.com/air";
tag_summary = "This host is installed with Adobe Air and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803454);
  script_version("$Revision: 18 $");
  script_cve_id("CVE-2012-5274", "CVE-2012-5275", "CVE-2012-5276", "CVE-2012-5277",
                "CVE-2012-5278", "CVE-2012-5279", "CVE-2012-5280");
  script_bugtraq_id(56412);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-28 16:57:06 +0530 (Thu, 28 Mar 2013)");
  script_name("Adobe Air Multiple Vulnerabilities - November12 (Windows)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/87064");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51213");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-24.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Air on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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
airVer = "";

# Check for Adobe Air 3.4.0.2540 and prior
airVer = get_kb_item("Adobe/Air/Win/Ver");
if(airVer)
{
  # Grep for version 3.4.0.2540 and prior
  if(version_is_less_equal(version:airVer, test_version:"3.4.0.2710"))
  {
    security_hole(0);
    exit(0);
  }
}
