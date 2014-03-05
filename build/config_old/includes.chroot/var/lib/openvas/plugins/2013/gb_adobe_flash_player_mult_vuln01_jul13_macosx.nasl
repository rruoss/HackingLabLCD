###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln01_jul13_macosx.nasl 11 2013-10-27 10:12:02Z jan $
#
# Adobe Flash Player Multiple Vulnerabilities-01 July13 (Mac OS X)
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
tag_impact = "
  Impact Level: System/Application";

if(description)
{
  script_id(803832);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3347", "CVE-2013-3345", "CVE-2013-3344");
  script_bugtraq_id(61048, 61045, 61043);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-25 17:41:58 +0530 (Thu, 25 Jul 2013)");
  script_name("Adobe Flash Player Multiple Vulnerabilities-01 July13 (Mac OS X)");

  tag_summary =
"This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple unspecified error exists and an integer overflow error exists
when resampling a PCM buffer.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary
code on the target system will cause heap-based buffer overflow or cause
memory corruption via unspecified vectors.";

  tag_affected =
"Adobe Flash Player before 11.7.700.232 and 11.8.x before 11.8.800.94 on
Mac OS X";

  tag_solution =
"Update to Adobe Flash Player version 11.7.700.232 or 11.8.800.94 or later
For updates refer to  http://get.adobe.com/flashplayer";

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
  script_xref(name : "URL" , value : "http://www.osvdb.com/94989");
  script_xref(name : "URL" , value : "http://www.osvdb.com/94988");
  script_xref(name : "URL" , value : "http://www.osvdb.com/94990");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53975");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-17.html");
  script_summary("Check for the vulnerable version of Adobe Flash Player on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
playerVer = "";

## Check for Adobe Flash Player
playerVer = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(playerVer)
{
  ## Grep for vulnerable version
  if(version_is_less(version:playerVer, test_version:"11.7.700.232") ||
     version_in_range(version:playerVer, test_version:"11.8.0", test_version2:"11.8.800.93"))
  {
    security_hole(0);
    exit(0);
  }
}
