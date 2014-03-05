###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-068.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Office Word Remote Code Execution Vulnerability (976307)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation could execute arbitrary code on the remote system
  via a specially crafted Word document.
  Impact Level: System/Application";
tag_affected = "Microsoft Office XP/2003.
  Microsoft Word Viewer 2003.";
tag_insight = "The flaws are due to memory corruption error when processing a malformed
  record within a Word document.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms09-068.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-068.";

if(description)
{
  script_id(900973);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-11 19:07:38 +0100 (Wed, 11 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3135");
  script_bugtraq_id(36950);
  script_name("Microsoft Office Word Remote Code Execution Vulnerability (976307)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37277/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3194");

  script_description(desc);
  script_summary("Check for the vulnerable Word/Word Viewer version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "secpod_ms_office_detection_900025.nasl");
  script_require_keys("SMB/Office/Word/Version",
                      "SMB/Office/WordView/Version");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("secpod_reg.inc");
include("version_func.inc");


if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

# Check for Office Word XP/2003
if(egrep(pattern:"^(10|11)\..*", string:get_kb_item("MS/Office/Ver")))
{
  # Grep for Office Word Version from KB
  wordVer = get_kb_item("SMB/Office/Word/Version");
  if(wordVer != NULL)
  {
    # Check for Office Word 10.0 < 10.0.6856.0 or 11.0 < 11.0.8313.0
    if(version_in_range(version:wordVer, test_version:"10.0",
                                        test_version2:"10.0.6855.9") ||
       version_in_range(version:wordVer, test_version:"11.0",
                                        test_version2:"11.0.8312.9"))
    {
      security_hole(0);
      exit(0);
    }
  }
}

# Check for Word Viewer
wordviewVer = get_kb_item("SMB/Office/WordView/Version");
if(wordviewVer != NULL)
{
  # Check for Word Viewer 11.0 < 11.0.8313.0
  if(version_in_range(version:wordviewVer, test_version:"11.0",
                                          test_version2:"11.0.8312.9")){
    security_hole(0);
  }
}
