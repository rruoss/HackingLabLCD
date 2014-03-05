###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_code_execution_vuln_apr11_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Adobe Products Arbitrary Code Execution Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let attackers to corrupt memory and execute
  arbitrary code on the system with elevated privileges.
  Impact Level: Application/System";
tag_affected = "Adobe Flash Player version 10.2.153.1 and prior on Windows
  Adobe Reader/Acrobat version 9.x to 9.4.3 and 10.x to 10.0.2 on windows.";
tag_insight = "The flaw is due to an error in handling 'SWF' file in adobe flash
  player and 'Authplay.dll' in Adobe acrobat/reader. which allows attackers
  to execute arbitrary code or cause a denial of service via crafted flash
  content.";
tag_solution = "No solution or patch is available as of 13th April, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.adobe.com/";
tag_summary = "This host has Adobe Acrobat or Adobe Reader or Adobe flash Player
  installed and is prone to code execution vulnerability.";

if(description)
{
  script_id(801921);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-0611");
  script_bugtraq_id(47314);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Products Arbitrary Code Execution Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "https://www.kb.cert.org/vuls/id/230057");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa11-02.html");
  script_xref(name : "URL" , value : "http://blogs.adobe.com/psirt/2011/04/security-advisory-for-adobe-flash-player-adobe-reader-and-acrobat-apsa11-02.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Acrobat, Reader and Adobe Flash Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl", "gb_adobe_flash_player_detect_win.nasl");
  script_require_keys("Adobe/Reader/Win/Ver", "Adobe/Acrobat/Win/Ver",
                      "AdobeFlashPlayer/Win/Ver");
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

# Check for Adobe Reader
readerVer = get_kb_item("Adobe/Reader/Win/Ver");
if(readerVer)
{
  if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.4.3") ||
     version_in_range(version:readerVer, test_version:"10.0", test_version2:"10.0.2"))
  {
    security_hole(0);
    exit(0);
  }
}

# Check for Adobe Acrobat
acrobatVer = get_kb_item("Adobe/Acrobat/Win/Ver");
if(acrobatVer)
{
  if(version_in_range(version:acrobatVer, test_version:"9.0", test_version2:"9.4.3") ||
     version_in_range(version:acrobatVer, test_version:"10.0", test_version2:"10.0.2"))
  {
    security_hole(0);
    exit(0);
  }
}

# Check for Adobe Flash Player version <= 10.2.153.1
flashVer = get_kb_item("AdobeFlashPlayer/Win/Ver");
if(flashVer)
{
  if(version_is_less_equal(version:flashVer, test_version:"10.2.153.1")){
    security_hole(0);
  }
}
