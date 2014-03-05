###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_dos_vuln_aug10_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Flash Player/Air Multiple Vulnerabilities - August10 (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code,
  cause denial-of-service conditions, or perform click-jacking attacks.
  Impact Level: Application/System.";
tag_affected = "Adobe AIR version prior to 2.0.3
  Adobe Flash Player version before 9.0.280 and 10.x before 10.1.82.76 on Linux";
tag_insight = "The flaws are due to memory corruptions and click-jacking issue via
  unspecified vectors.";
tag_solution = "Upgrade to Adobe Air 2.0.3 and Adobe Flash Player 9.0.280 or 10.1.82.76 or later
  For updates refer to http://get.adobe.com/air
  http://www.adobe.com/support/flashplayer/downloads.html";
tag_summary = "This host is installed with Adobe Flash Player/Air and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(801256);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)");
  script_cve_id("CVE-2010-0209", "CVE-2010-2213", "CVE-2010-2215",
                "CVE-2010-2214", "CVE-2010-2216");
  script_bugtraq_id(42341);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Flash Player/Air Multiple Vulnerabilities - August10 (Linux)");
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
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb10-16.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Flash Player/Air");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_require_keys("AdobeFlashPlayer/Linux/Ver", "Adobe/Air/Linux/Ver");
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
playerVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(playerVer != NULL)
{
  if(version_is_less(version:playerVer, test_version:"9.0.280") ||
     version_in_range(version:playerVer, test_version:"10.0", test_version2:"10.1.82.75"))
  {
    security_hole(0);
    exit(0);
  }
}

# Check for Adobe Air
airVer = get_kb_item("Adobe/Air/Linux/Ver");
if(airVer != NULL)
{
  if(version_is_less(version:airVer, test_version:"2.0.3")){
    security_hole(0);
  }
}
