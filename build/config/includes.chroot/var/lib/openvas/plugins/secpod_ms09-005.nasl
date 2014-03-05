###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-005.nasl 15 2013-10-27 12:49:54Z jan $
#
# Vulnerabilities in Microsoft Office Visio Could Allow Remote Code Execution (957634)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
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
tag_impact = "Successful exploitation could lead to memory corruption by sending
  a specially crafted Visio file.
  Impact Level: System";
tag_affected = "Microsoft Office Visio 2002/2003/2007 on Windows";
tag_insight = "- Error exists when parsing object data during opening of Visio files.
  - Pop-Up error while copying object data in memory.
  - Error while handling of memory when opening Visio files.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms09-005.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-005.";

if(description)
{
  script_id(900080);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0095", "CVE-2009-0096", "CVE-2009-0097");
  script_bugtraq_id(33659, 33660, 33661);
  script_name("Vulnerabilities in Microsoft Office Visio Could Allow Remote Code Execution (957634)");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/957634");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS09-005");

  script_description(desc);
  script_summary("Check for the vulnerable File Version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

ovPath = "";
exeVer = "";

ovPath = registry_get_sz(item:"Path",
         key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\visio.exe");

if(!ovPath){
  exit(0);
}

exeVer = fetch_file_version(sysPath:ovPath, file_name:"visio.exe");
if(!exeVer){
  exit(0);
}

# Check for visio.exe version for 2002, 2003 and 2007
if(version_in_range(version:exeVer, test_version:"10.0", test_version2:"10.0.6885.3") ||
   version_in_range(version:exeVer, test_version:"11.0", test_version2:"11.0.8206.0") ||
   version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6325.4999")){
  security_hole(0);
}