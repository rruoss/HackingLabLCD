###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_code_exec_vuln_win_jun10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Products Remote Code Execution Vulnerability - jun10 (Win)
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
tag_solution = "For Adobe Flash Player,
  Update to Adobe Flash Player 10.1.53.64 or 9.0.277.0 or later,
  For updates refer to http://www.adobe.com/support/flashplayer/downloads.html

  Fix: For Adobe Reader/Acrobat,
  No solution or patch is available as of 11th June, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.adobe.com

  Workaround:
  Apply work around for Adobe Reader/Acrobat from below link,
  http://www.adobe.com/support/security/advisories/apsa10-01.html";

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code by tricking a user into opening a specially crafted PDF file.
  Impact Level: Application";
tag_affected = "Adobe Reader/Acrobat version 9.x to 9.3.2
  Adobe Flash Player version 9.0.x to 9.0.262 and 10.x to 10.0.45.2";
tag_insight = "The flaw is due to a memory corruption error in the 'authplay.dll' library
  and 'SWF' file when processing ActionScript Virtual Machine 2 (AVM2)
  'newfunction' instructions within Flash content in a PDF document.";
tag_summary = "This host is installed with Adobe products and is prone to
  remote code execution vulnerability.";

if(description)
{
  script_id(801360);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)");
  script_cve_id("CVE-2010-1297");
  script_bugtraq_id(40586);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Products Remote Code Execution Vulnerability - jun10 (Win)");
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

  script_xref(name : "URL" , value : "http://osvdb.org/65141");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1349");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1348");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa10-01.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader/Acrobat/Flash Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl",
                      "gb_adobe_flash_player_detect_win.nasl");
  script_require_keys("AdobeFlashPlayer/Win/Ver", "Adobe/Acrobat/Win/Ver",
                      "Adobe/Reader/Win/Ver");
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

# Check for Adobe Flash Player
pVer = get_kb_item("AdobeFlashPlayer/Win/Ver");
if(pVer != NULL)
{
  #  Adobe Flash Player version 9.0.0 to 9.0.262 and 10.x to 10.0.45.2
  if(version_in_range(version:pVer, test_version:"9.0.0", test_version2:"9.0.262") ||
     version_in_range(version:pVer, test_version:"10.0", test_version2:"10.0.45.2"))
  {
    security_hole(0);
    exit(0);
  }
}

# Adobe Acrobat
acVer = get_kb_item("Adobe/Acrobat/Win/Ver");
if(acVer != NULL)
{
  # Grep for Adobe Acrobat version 9.0 to 9.3.2
  if(version_in_range(version:acVer, test_version:"9.0", test_version2:"9.3.2"))
  {
    security_hole(0);
    exit(0);
  }
}

# Adobe Reader
arVer = get_kb_item("Adobe/Reader/Win/Ver");
if(arVer != NULL)
{
  # Grep for Adobe Reader version 9.0 to 9.3.2
  if(version_in_range(version:arVer, test_version:"9.0", test_version2:"9.3.2")){
    security_hole(0);
  }
}
