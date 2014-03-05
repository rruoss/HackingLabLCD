###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln_mar09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Adobe Flash Player Multiple Vulnerabilities - Mar09 (Win)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_solution = "Update to version 1.5.1 for Adobe Air.
  http://get.adobe.com/air

  Update to Adobe Flash Player 9.0.159.0 or 10.0.22.87 and
  Adobe CS3/CS4, Flex 3
  http://get.adobe.com/flashplayer
  http://www.adobe.com/support/flashplayer/downloads.html#fp9";

tag_impact = "Successful exploitation will allow remote attackers to cause remote code
  execution, compromise system privileges or may cause exposure of sensitive
  information.
  Impact Level: System/Application";
tag_affected = "Adobe Flex version 3.x or 2.x
  Adobe AIR version prior to 1.5.1
  Adobe Flash CS3/CS4 Professional
  Adobe Flash Player 9 version prior to 9.0.159.0
  Adobe Flash Player 10 version prior to 10.0.22.87";
tag_insight = "- Error while processing multiple references to an unspecified object which
    can be exploited by tricking the user to accessing a malicious crafted SWF
    file.
  - Input validation error in the processing of SWF file.
  - Error while displaying the mouse pointer on Windows which may cause
    'Clickjacking' attacks.";
tag_summary = "This host is installed with Adobe Products and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(800359);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-10 11:59:23 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0114", "CVE-2009-0519", "CVE-2009-0520", "CVE-2009-0522");
  script_bugtraq_id(33890);
  script_name("Adobe Flash Player Multiple Vulnerabilities - Mar09 (Win)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/34012");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-01.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Flash Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_require_keys("AdobeFlashPlayer/Win/Ver", "Adobe/Air/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

# Check for Adobe Flash Player version prior to 9.0.159.0 or 10.0.22.87
playerVer = get_kb_item("AdobeFlashPlayer/Win/Ver");
if(playerVer != NULL)
{
  if(version_is_less(version:playerVer, test_version:"9.0.159.0") ||
     version_in_range(version:playerVer, test_version:"10.0",
                                         test_version2:"10.0.22.86"))
  {
    security_hole(0);
    exit(0);
  }
}

# Check for Adobe Air version prior to 1.5.1
airVer = get_kb_item("Adobe/Air/Win/Ver");
if(airVer != NULL)
{
  if(version_is_less(version:airVer, test_version:"1.5.1")){
    security_hole(0);
  }
}