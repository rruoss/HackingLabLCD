###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-103.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Publisher Remote Code Execution Vulnerability (2292970)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow an attacker to execute arbitrary code on
  the remote system.
  Impact Level: Application";
tag_affected = "Microsoft Publisher 2010
  Microsoft Publisher 2002 Service Pack 3
  Microsoft Publisher 2003 Service Pack 3
  Microsoft Publisher 2007 Service Pack 2";
tag_insight = "The flaw is due to the way  Microsoft Publisher parses specially
  crafted Publisher files, which could allow attackers to execute arbitrary code
  by tricking a user into opening a specially crafted Publisher file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms10-103.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-103.";

if(description)
{
  script_id(902274);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-15 14:53:45 +0100 (Wed, 15 Dec 2010)");
  script_cve_id("CVE-2010-2569", "CVE-2010-2570", "CVE-2010-2571", "CVE-2010-3954",
                "CVE-2010-3955");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Publisher Remote Code Execution Vulnerability (2292970)");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2409055");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2284697");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2284695");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2284692");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms10-103.mspx");

  script_description(desc);
  script_summary("Check for the Microsoft Publisher version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "secpod_ms_office_detection_900025.nasl");
  script_require_keys("SMB/WindowsVersion", "SMB/Office/Publisher/Version");
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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Grep for Office Publisher Version from KB
pubVer = get_kb_item("SMB/Office/Publisher/Version");
if(!isnull(pubVer))
{
  ## Grep for Mspub.exe version 10 < 10.0.6867.0, 11 < 11.0.8329.0,
  ##  12 < 12.0.6546.5000 , 14 < 14.0.5126.5000
  if(version_in_range(version:pubVer, test_version:"10.0",test_version2:"10.0.6866.0") ||
     version_in_range(version:pubVer, test_version:"11.0",test_version2:"11.0.8328.0") ||
     version_in_range(version:pubVer, test_version:"12.0",test_version2:"12.0.6546.4999")|| 
     version_in_range(version:pubVer, test_version:"14.0",test_version2:"14.0.5126.4999"))
  {
    security_hole(0);
    exit(0);
  }
}
