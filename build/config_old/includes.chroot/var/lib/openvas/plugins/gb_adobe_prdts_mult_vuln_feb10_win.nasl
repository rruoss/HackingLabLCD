###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_feb10_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Flash Player/Air Multiple Vulnerabilities - feb10 (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to bypass security
  restrictions.
  Impact Level: Application";
tag_affected = "Adobe AIR version prior to 1.5.3.9130
  Adobe Flash Player 10 version prior to 10.0.45.2 on Windows";
tag_insight = "Cross domain vulnerabilities present in Adobe Flash Player/Adobe Air allows
  remote attackers to bypass intended sandbox restrictions and make
  cross-domain requests via unspecified vectors.";
tag_solution = "Update to Adobe Air 1.5.3.9130 or Adobe Flash Player 10.0.45.2,
  http://get.adobe.com/air
  http://www.adobe.com/support/flashplayer/downloads.html";
tag_summary = "This host is installed with Adobe Flash Player/Air and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(800475);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-0186", "CVE-2010-0187");
  script_bugtraq_id(38198, 38200);
  script_name("Adobe Flash Player/Air Multiple Vulnerabilities -feb10 (Win)");
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
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=563819");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb10-06.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Flash Player/Air");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_require_keys("AdobeFlashPlayer/Win/Ver", "Adobe/Air/Win/Ver");
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

# Check for Adobe Flash Player
playerVer = get_kb_item("AdobeFlashPlayer/Win/Ver");
if(playerVer != NULL)
{
  # Grep for version 10.x < 10.0.45.2
  if(version_in_range(version:playerVer, test_version:"10.0", test_version2:"10.0.45.1"))
  {
    security_hole(0);
    exit(0);
  }
}

# Check for Adobe Air
airVer = get_kb_item("Adobe/Air/Win/Ver");
if(airVer != NULL)
{
  # Grep for version < 1.5.3.9130
  if(version_is_less(version:airVer, test_version:"1.5.3.9130")){
    security_hole(0);
  }
}
