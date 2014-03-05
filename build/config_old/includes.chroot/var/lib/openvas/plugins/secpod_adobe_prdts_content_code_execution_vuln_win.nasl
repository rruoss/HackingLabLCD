###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_content_code_execution_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Products Content Code Execution Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_affected = "Adobe Reader/Acrobat version 9.3.4 and prior on Windows.
  Adobe Flash Player version 10.1.82.76 and prior on Windows";
tag_insight = "The flaw is caused by an unspecified error when processing malformed 'Flash'
  or '3D' and 'Multimedia' content within a PDF document, which could be
  exploited by attackers to execute arbitrary code by convincing a user to open
  a specially crafted PDF file.";
tag_solution = "No solution or patch is available as of 17th September 2010, Information
  regarding this issue will be updated once the solution details are available.
  For details refer, http://www.adobe.com/downloads/";
tag_summary = "This host has Adobe Acrobat or Adobe Reader or Adobe flash Player
  installed, and is prone to code execution vulnerability.";

if(description)
{
  script_id(902303);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2010-2884");
  script_name("Adobe Products Content Code Execution Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/61771");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2349");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2348");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa10-03.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Acrobat, Reader and Adobe Flash Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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

# Check for Adobe Reader version <= 9.3.4
readerVer = get_kb_item("Adobe/Reader/Win/Ver");
if(readerVer)
{
  if(version_is_less_equal(version:readerVer, test_version:"9.3.4"))
  {
    security_hole(0);
    exit(0);
  }
}

# Check for Adobe Acrobat version <= 9.3.4
acrobatVer = get_kb_item("Adobe/Acrobat/Win/Ver");
if(acrobatVer)
{
  if(version_is_less_equal(version:acrobatVer, test_version:"9.3.4")){
    security_hole(0);
    exit(0);
  }
}

# Check for Adobe Flash Player version <= 10.1.82.76
flashVer = get_kb_item("AdobeFlashPlayer/Win/Ver");
if(flashVer)
{
  if(version_is_less_equal(version:flashVer, test_version:"10.1.82.76")){
    security_hole(0);
  }
}
