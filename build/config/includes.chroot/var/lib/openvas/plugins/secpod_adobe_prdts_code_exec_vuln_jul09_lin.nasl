###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_code_exec_vuln_jul09_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Adobe Products '.pdf' and '.swf' Code Execution Vulnerability - July09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to cause code execution
  on the affected application.
  Impact Level: Application";
tag_affected = "Adobe Reader/Acrobat version 9.x to 9.1.2
  Adobe Flash Player version 9.x to 9.0.159.0 and 10.x to 10.0.22.87 on Linux.";
tag_insight = "- An unspecified error exists in Adobe Flash Player which can be exploited
    via a specially crafted Flash application in a '.pdf' file.
  - Error occurs in 'authplay.dll' in Adobe Reader/Acrobat whlie processing
    '.swf' content and can be exploited to execute arbitrary code.";
tag_solution = "Upgrade to Adobe Reader/Acrobat version 9.1.3 or later
  Upgrade to Adobe Flash Player 9.0.246.0 or 10.0.32.18 or later
  For updates refer to http://www.adobe.com/";
tag_summary = "This host is installed with Adobe products and is prone to remote
  code execution vulnerability.";

if(description)
{
  script_id(900807);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1862");
  script_bugtraq_id(35759);
  script_name("Adobe Products '.pdf' and '.swf' Code Execution Vulnerability - July09 (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35948/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35949/");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/259425");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa09-03.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl",
                      "gb_adobe_prdts_detect_lin.nasl");
  script_require_keys("AdobeFlashPlayer/Linux/Ver", "Adobe/Reader/Linux/Version");
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

# Check for Adobe Flash Player version 9.x to 9.0.159.0 or 10.x to 10.0.22.87
playerVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(playerVer != NULL)
{
  if(version_in_range(version:playerVer, test_version:"9.0", test_version2:"9.0.159.0") ||
     version_in_range(version:playerVer, test_version:"10.0", test_version2:"10.0.22.87"))
  {
    security_hole(0);
    exit(0);
  }
}

# Check for Adobe Reader version 9.x to 9.1.2
readerVer = get_kb_item("Adobe/Reader/Linux/Version");
if(readerVer != NULL)
{
  if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.1.2")){
    security_hole(0);
  }
}
