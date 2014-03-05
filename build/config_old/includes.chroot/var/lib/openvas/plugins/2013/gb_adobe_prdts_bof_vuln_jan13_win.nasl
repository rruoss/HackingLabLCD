###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_bof_vuln_jan13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Adobe Flash Player Buffer Overflow Vulnerability (Windows)
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code or cause denial of service condition.
  Impact Level: System/Application";

tag_affected = "Adobe Flash Player version before 10.3.183.50, 11.x before 11.5.502.146 on Windows";
tag_insight = "An integer overflow error within 'flash.display.BitmapData()', which can be
  exploited to cause a heap-based buffer overflow.";
tag_solution = "Update to Adobe Flash Player version 10.3.183.50 or 11.5.502.146 or later,
  For updates refer to http://get.adobe.com/flashplayer";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(803152);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-0630");
  script_bugtraq_id(57184);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-15 15:38:40 +0530 (Tue, 15 Jan 2013)");
  script_name("Adobe Flash Player Buffer Overflow Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/88969");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51771");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027950");
  script_xref(name : "URL" , value : "http://www.osvdb.org/show/osvdb/88969");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-01.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Flash Player on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Ver");
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
playerVer = "";

# Check for Adobe Flash Player
playerVer = get_kb_item("AdobeFlashPlayer/Win/Ver");
if(playerVer)
{
  # Grep for version less than 10.3.183.50 and 11.x less than 11.5.502.135
  if(version_is_less(version: playerVer, test_version:"10.3.183.50") ||
     version_in_range(version: playerVer, test_version:"11.0", test_version2:"11.5.502.145"))
  {
    security_hole(0);
    exit(0);
  }
}
