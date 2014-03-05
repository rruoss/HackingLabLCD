###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_dec09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Adobe Flash Player/Air Multiple Vulnerabilities - dec09 (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code,
  gain elevated privileges, gain knowledge of certain information and conduct
  clickjacking attacks.
  Impact Level: System/Application";
tag_affected = "Adobe AIR version prior to 1.5.3
  Adobe Flash Player 10 version prior to 10.0.42.34 on Windows";
tag_insight = "The multiple Flaws are due to:
  - An error occured while parsing JPEG dimensions contained within an SWF file
    can be exploited to cause a heap-based buffer overflow.
  - An unspecified error may allow injection of data and potentially lead to
    execution of arbitrary code.
  - An unspecified error possibly related to 'getProperty()' can be exploited
    to corrupt memory and may allow execution of arbitrary code.
  - An unspecified error can be exploited to corrupt memory and may allow
    execution of arbitrary code.
  - An integer overflow error when generating ActionScript exception handlers
    in 'Verifier::parseExceptionHandlers()' can be exploited to corrupt memory.
  - Various unspecified errors may potentially allow execution of arbitrary code.
  - An error may disclose information about local file names.";
tag_solution = "Update to Adobe Air 1.5.3 or Adobe Flash Player 10.0.42.34
  http://get.adobe.com/air
  http://www.adobe.com/support/flashplayer/downloads.html";
tag_summary = "This host is installed with Adobe Flash Player/Air and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(801083);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-17 08:14:37 +0100 (Thu, 17 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3794", "CVE-2009-3796", "CVE-2009-3797", "CVE-2009-3798",
                "CVE-2009-3799", "CVE-2009-3800", "CVE-2009-3951");
  script_bugtraq_id(37266, 37270, 37273, 37275, 37267, 37269, 37272 );
  script_name("Adobe Flash Player/Air Multiple Vulnerabilities - dec09 (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37584");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3456");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-19.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Flash Player/Air");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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
  # Grep for version 10.x < 10.0.32.18
  if(version_in_range(version:playerVer, test_version:"10.0", test_version2:"10.0.42.33")) {
    security_hole(0);
  }
}

# Check for Adobe Air
airVer = get_kb_item("Adobe/Air/Win/Ver");
if(airVer != NULL)
{
  # Grep for version < 1.5.3
  if(version_is_less(version:airVer, test_version:"1.5.3")){
    security_hole(0);
  }
}
